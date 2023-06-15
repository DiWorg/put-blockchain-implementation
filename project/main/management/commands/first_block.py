import hashlib
from django.core.management.base import BaseCommand, CommandError
from ...models import Block

class Command(BaseCommand):

    def handle(self, *args, **kwargs):
        genesis_block = Block.objects.create(
            block_number=1,
            previous_block=None,
            nonce=0,
            block_hash=hashlib.sha256(b'genesis_block_data').hexdigest(),
            mined=False,
            validated = False,
            votes=0

        )
