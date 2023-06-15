import hashlib
from datetime import timedelta

from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.shortcuts import render
from django.contrib.auth import login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import *


def loginView(request):
    if request.user.is_authenticated:
        return redirect(start_page)

    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            check_votes(request)
            if request.GET.get('next'):
                return redirect(request.GET.get("next"))
            else:
                return redirect(start_page)
        else:
            messages.add_message(request, messages.ERROR, 'Login unsuccessful! Wrong username and/or password!')
    else:
        form = AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})


@login_required
def start_page(request):
    if request.method == 'GET':
        return render(request, 'shared/start_page.html')


@login_required
def add_transaction(request):
    if request.method == 'GET':
        user_list = User.objects.order_by("username")
        return render(request, 'project/transaction_add.html',
                      {"users": user_list})


@login_required
def add_transaction_manage(request):
    if request.method == 'POST':
        if request.POST.get('user_id') and request.POST.get('amount'):
            transaction = Transaction()
            transaction.sender = request.user
            transaction.recipient = User.objects.get(id=request.POST.get('user_id'))
            transaction.amount = request.POST.get('amount')
            transaction.save()
            transaction.transaction_hash = transaction.hash_tansaction()
            transaction.sign_transaction()
            transaction.save()

            if Block.objects.filter(mined=False).exists():
                current_block = Block.objects.filter(mined=False).latest('id')
                if current_block.is_full():
                    # Create a new block
                    new_block = Block(previous_block=current_block, nonce=current_block.generate_new_nonce(),
                                      block_number=current_block.block_number + 1, )
                    new_block.save()
                    current_block = new_block
                current_block.transactions.add(transaction)
            else:
                current_block = Block.objects.filter(mined=True).latest('id')
                new_block = Block(previous_block=current_block, nonce=current_block.generate_new_nonce(),
                                  block_number=current_block.block_number + 1, )
                new_block.save()
                current_block = new_block
                current_block.transactions.add(transaction)

            messages.add_message(request, messages.SUCCESS, 'Transaction will be added to the blockchain!')
            return redirect(add_transaction)
        else:
            messages.add_message(request, messages.ERROR, 'Error! Some fields are empty!')
            return redirect(add_transaction)
    return redirect(add_transaction)


@login_required
def mine_block_manage(request):
    if request.method == 'POST':
        block = Block.objects.filter(mined=False).first()
        if block:
            try:
                block.validate_short()
                block.mine_block()
                block.mined = True
                block.votes = 1
                block.save()
                new_vote = Vote(block=block, user=request.user, rate=True)
                new_vote.save()
                messages.add_message(request, messages.SUCCESS, 'Block mined successfully.')
            except ValidationError as e:
                for transaction in block.transactions.all():
                    transaction.delete()
                block.delete()
                print(e)
                messages.add_message(request, messages.ERROR, 'Validation error has occurred. Block and transactions '
                                                              'deleted.')
        else:
            messages.add_message(request, messages.ERROR, 'No unmined blocks available.')
    return redirect(show_blockchain)


@login_required
def show_blockchain(request):
    if request.method == 'GET':
        block_list_unchecked = Block.objects.filter(mined=True, validated=True).all()
        block_list = []
        if block_list_unchecked:
            for block in block_list_unchecked:
                try:
                    block.validate()
                    block_list.append(block)
                except ValidationError as e:

                    print(e)
                    messages.add_message(request, messages.ERROR, 'Validation error has occurred. Block and '
                                                                  'transactions deleted.')
        if block_list:
            transactions = []
            for block in block_list:
                for transaction in block.transactions.all():
                    new_transaction = {"block_number": block.block_number, "block_hash": block.block_hash,
                                       "block_previous_hash": block.previous_block.block_hash if block.previous_block
                                       else DEFAULT_PREVIOUS_BLOCK_HASH,
                                       "block_timestamp": block.timestamp, "transaction_timestamp":
                                           transaction.timestamp, "transaction_sender": transaction.sender.username,
                                       "transaction_recipent": transaction.recipient.username, "transaction_amount":
                                           transaction.amount, "transaction_hash": transaction.transaction_hash}
                    transactions.append(new_transaction)
            paginator = Paginator(transactions, 10)
            page_number = request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            nums = "a" * page_obj.paginator.num_pages

            return render(request, 'project/blockchain.html', {'transactions': transactions, 'page_obj': page_obj,
                                                               'nums': nums})

        return render(request, 'project/blockchain.html')


@login_required()
def check_votes(request):
    block_list_to_validate = Block.objects.filter(validated=False).all()
    for block in block_list_to_validate:
        if Vote.objects.filter(user=request.user, block=block).first():
            print("??????")
            pass
        else:
            try:
                block.validate()
                new_vote = Vote(block=block, user=request.user, rate=True)
                new_vote.save()
                block.votes = block.votes + 1
                block.save()
            except ValidationError as e:
                new_vote = Vote(block=block, user=request.user, rate=False)
                new_vote.save()
                block.votes = block.votes + 1
                block.save()

        end_date = datetime.now()
        start_date = end_date - timedelta(days=3)
        if block.votes >= User.objects.filter(last_login__range=(start_date, end_date)).count():
            yes = Vote.objects.filter(block=block, rate=True).count()
            no = Vote.objects.filter(block=block, rate=False).count()
            if yes >= no:
                block.validated = True
                block.save()
            else:
                block.delete()
