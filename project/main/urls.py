from django.urls import path
from . import views

urlpatterns = [
    path('', views.loginView, name='login'),
    path('.', views.loginView, name='login'),
    path('login', views.loginView, name='login'),
    path('start_page', views.start_page, name="start_page"),
    path('add_transaction', views.add_transaction, name="add_transaction"),
    path('add_transaction_manage', views.add_transaction_manage, name="add_transaction_manage"),
    path('blockchain', views.show_blockchain, name="show_blockchain"),
    path('mine_block_manage', views.mine_block_manage, name="mine_block_manage")
]

