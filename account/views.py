from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, SimpleSondageSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from account.models import Sondage, Answer  
from account.serializers import SondageSerializer, AnswerSerializer 
from rest_framework import generics, permissions
from account.models import User


# Generate Token Manually
def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user)
        return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        }

class UserRegistrationView(APIView):
        renderer_classes = [UserRenderer]
        def post(self, request, format=None):
                serializer = UserRegistrationSerializer(data=request.data)
                if serializer.is_valid(raise_exception=True):
                        user = serializer.save()
                        token = get_tokens_for_user(user)
                        return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)

            if user is not None:
                token = get_tokens_for_user(user)

                response_data = {
                    'token': token,
                    'user_id': user.id,
                    'email': user.email,
                    'username': user.name,
                    'msg': 'Login Success',
                }

                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
        renderer_classes = [UserRenderer]
        permission_classes = [IsAuthenticated]
        def get(self, request, format=None):
                serializer = UserProfileSerializer(request.user)
                return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
        renderer_classes = [UserRenderer]
        permission_classes = [IsAuthenticated]
        def post(self, request, format=None):
                serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
                if serializer.is_valid(raise_exception=True):
                        return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(APIView):
        renderer_classes = [UserRenderer]
        def post(self, request, format=None):
                serializer = SendPasswordResetEmailSerializer(data=request.data)
                if serializer.is_valid(raise_exception=True):
                        return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetView(APIView):
        renderer_classes = [UserRenderer]
        def post(self, request, uid, token, format=None):
                serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
                if serializer.is_valid(raise_exception=True):
                        return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
# Renouveler le token
class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            new_access_token = str(token.access_token)

            return Response({'access_token': new_access_token}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': 'Invalid refresh token.'}, status=status.HTTP_400_BAD_REQUEST)
        
        
        # Med Bechir
# class SondageOptionListCreateView(generics.ListCreateAPIView):
#     queryset = Sondage.objects.all()
#     serializer_class = SondageSerializer

class SondageListCreateView(generics.ListCreateAPIView):
    queryset = Sondage.objects.all()
    serializer_class = SondageSerializer

    def perform_create(self, serializer):
        sondage = serializer.save(owner=self.request.user)
        survey_url = sondage.get_survey_url()
        return Response({'survey_url': survey_url})

class SondageDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Sondage.objects.all()
    serializer_class = SondageSerializer

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        sondage_id = self.kwargs.get('pk')
        answers = Answer.objects.filter(sondage=sondage_id)
        answer_serializer = AnswerSerializer(answers, many=True)
        response.data['answers'] = answer_serializer.data
        return response


class SondageDetailSimpleView(generics.RetrieveAPIView):
    # permission_classes = [IsAuthenticated]
    queryset = Sondage.objects.all()
    serializer_class = SimpleSondageSerializer
    lookup_field = 'slug'

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class AnswerCreateView(generics.CreateAPIView):
    # permission_classes = [IsAuthenticated]
    queryset = Answer.objects.all()
    serializer_class = AnswerSerializer

    def perform_create(self, serializer):
        sondage_id = self.request.data.get('sondage_id')
        serializer.save(sondage_id=sondage_id)


        

class SondageResultsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk, format=None):
        answers = Answer.objects.filter(sondage=pk)
        answer_serializer = AnswerSerializer(answers, many=True)

        response_data = {
            'sondage_id': pk,
            'answers': answer_serializer.data,
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
