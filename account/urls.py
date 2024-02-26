from django.urls import path, include
from account.views import UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView, CheckEmailExistsView
from account.views import SondageListCreateView, SondageDetailView, AnswerCreateView, SondageResultsView, SondageDetailSimpleView, RefreshTokenView  


urlpatterns = [
        path('register/', UserRegistrationView.as_view(), name='register'),
        path('check-email/', CheckEmailExistsView.as_view(), name='check_email_exists'),
        path('login/', UserLoginView.as_view(), name='login'),
        path('profile/', UserProfileView.as_view(), name='profile'),
        path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
        path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
        path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
        path('refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),
        path('sondages/', SondageListCreateView.as_view(), name='creation-de-sondage'), 
        path('sondages/<int:pk>/', SondageDetailView.as_view(), name='sondage-detail'),
        path('sondages/choix/', AnswerCreateView.as_view(), name='choix-sondage'),
        path('sondages/<int:pk>/resultats/', SondageResultsView.as_view(), name='resulats-sondages'),
        path('sondages/<slug:slug>/', SondageDetailSimpleView.as_view(), name='sondage-detail'),
        
]
