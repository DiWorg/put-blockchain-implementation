import binascii
import hashlib
import random
from decimal import Decimal

from cryptography import utils
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.contrib.auth.models import User
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from django.utils.datetime_safe import datetime

DEFAULT_PREVIOUS_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
MAX_TRANSACTIONS_PER_BLOCK = 10
DIFFICULTY = 2  # number of leading zeros required in the block hash


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    private_key = models.TextField()
    public_key = models.TextField()

    class Meta:
        verbose_name = "profil"
        verbose_name_plural = "profile"
        default_permissions = ()


class Transaction(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_transactions')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(Decimal('0.01'))])
    timestamp = models.DateTimeField(auto_now_add=True, blank=True)
    transaction_hash = models.CharField(max_length=128)
    signature = models.BinaryField()

    def sign_transaction(self):
        private_key_str = self.sender.profile.private_key

        private_key_bytes = private_key_str.encode('utf-8')
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )

        message = self.get_transaction_message()
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.signature = signature

    def verify_signature(self):
        public_key = self.sender.profile.public_key
        public_key_bytes = public_key.encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_bytes)
        message = self.get_transaction_message()
        try:
            public_key.verify(
                bytes(self.signature),
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except ValidationError as e:
            return False

    def hash_tansaction(self):
        message = self.get_transaction_message()
        algorithm = hashes.SHA256()
        hasher = hashes.Hash(algorithm)
        hasher.update(message.encode('utf-8'))
        hash_bytes = hasher.finalize()
        hash_hex = binascii.hexlify(hash_bytes).decode('utf-8')
        print(message)
        print(hash_hex)
        return hash_hex

    def get_transaction_message(self):
        number = float(self.amount)
        amount_format = "{:.2f}"
        transaction_string = (
                str(self.sender.id) +
                str(self.recipient.id) +
                str(amount_format.format(number)) +
                str(self.timestamp)
        )
        return transaction_string

    def validate_signature(self):
        if not self.verify_signature():
            print("here4")
            raise ValidationError("Transaction signature is invalid.")

    def validate_hash(self):
        if self.transaction_hash != self.hash_tansaction():
            print("here3")
            raise ValidationError("Transaction hash is invalid.")

    def validate(self):
        super().clean()
        self.validate_signature()
        self.validate_hash()

    class Meta:
        verbose_name = "transakcja"
        verbose_name_plural = "transakcje"
        default_permissions = ()

    def __str__(self):
        return str(self.sender.id) + str(' - ') + str(self.recipient.id) + str(' - ') + str(self.timestamp)


class Block(models.Model):
    block_number = models.IntegerField()
    timestamp = models.DateTimeField(default=datetime.now, blank=True)
    transactions = models.ManyToManyField(Transaction)
    previous_block = models.OneToOneField('self', on_delete=models.CASCADE, null=True, blank=True)
    nonce = models.BigIntegerField(null=True)
    block_hash = models.CharField(max_length=124)
    mined = models.BooleanField(default=False)
    validated = models.BooleanField(default=False)
    votes = models.IntegerField(default=0)

    def hash_function(self):
        message = self.get_block_message()
        algorithm = hashes.SHA256()
        hasher = hashes.Hash(algorithm)
        hasher.update(message.encode('utf-8'))
        hash_bytes = hasher.finalize()
        hash_hex = binascii.hexlify(hash_bytes).decode('utf-8')
        return hash_hex

    def get_block_message(self):
        block_string = (
                str(self.block_number) +
                str(self.timestamp) +
                str(self.calculate_merkle_root()) +
                str(self.previous_block.block_hash if self.previous_block else DEFAULT_PREVIOUS_BLOCK_HASH) +
                str(self.nonce)
        )
        return block_string

    def mine_block(self):
        target = "0" * DIFFICULTY

        while True:
            self.nonce = random.randint(0, 2 ** 32 - 1)
            block_hash = self.hash_function()

            if block_hash.startswith(target):
                self.block_hash = block_hash
                break

    # hash for representing all transactions
    def calculate_merkle_root(self):
        hashes = [t.transaction_hash for t in self.transactions.all()]

        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # Duplicate the last hash if the number of hashes is odd

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined_hash = hashlib.sha256(hashlib.sha256(hashes[i].encode('utf-8')).digest() +
                                               hashlib.sha256(hashes[i + 1].encode('utf-8')).digest()).digest()
                new_hashes.append(combined_hash.hex())
            hashes = new_hashes
        return hashes[0] if hashes else None

    def is_full(self):
        return self.transactions.count() >= MAX_TRANSACTIONS_PER_BLOCK

    def generate_new_nonce(self):
        return random.randint(0, 2 ** 32 - 1)

    def validate_block(self):
        # Perform block validation checks
        if not self.transactions.exists():
            print("here1")
            raise ValidationError("Block must have at least one transaction.")

    def validate_hash(self):
        # Perform hash validation checks
        if self.block_hash != self.hash_function():
            print("here2")
            raise ValidationError("Block hash is invalid.")

    def validate_transactions(self):
        transactions = self.transactions.all()
        for transaction in transactions:
            transaction.validate()

    def validate(self):
        self.validate_block()
        self.validate_hash()
        self.validate_transactions()

    def validate_short(self):
        self.validate_block()

    class Meta:
        verbose_name = "blok"
        verbose_name_plural = "bloki"
        default_permissions = ()

    def __str__(self):
        return str(self.block_number)


class Vote(models.Model):
    block = models.ForeignKey(Block, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rate = models.BooleanField(default=False)

    def __str__(self):
        return str(self.block.block_number) + " - " + str(self.user.username)