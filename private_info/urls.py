from django.urls import path

from . import views


app_name = "private_info"
urlpatterns = [
    path('password/<str:password_type>/', views.vf_password, name='vn-password'),
    path('password/new/<str:password_type>/', views.vf_password_new, name='vn-password-new'),
    path('password/modify/<str:password_type>/', views.vf_password_modify, name='vn-password-modify'),
    path('password/display/<str:password_type>/', views.vf_password_display, name='vn-password-display'),
    path('password/auth/<str:password_type>/<str:action>/', views.vf_password_auth, name='vn-password-auth'),

    path('data/<str:data_type>/', views.vf_data, name='vn-data'),
    path('data/new/<str:data_type>/', views.vf_data_new, name='vn-data-new'),
    path('data/delete/<str:data_type>/<int:data_id>/', views.vf_data_delete, name='vn-data-delete'),
    path('data/modify/<str:data_type>/<int:data_id>/', views.vf_data_modify, name='vn-data-modify'),
    path('data/display/<str:data_type>/<int:data_id>/', views.vf_data_display, name='vn-data-display'),
    path('data/auth/<str:data_type>/<int:data_id>/<str:action>/', views.vf_data_auth, name='vn-data-auth'),

    path('logout/', views.vf_logout, name='vn-logout'),
    path('registry/', views.vf_registry, name='vn-registry'),
    path('login_password_modify/', views.vf_login_password_modify, name='vn-login-password-modify'),


]