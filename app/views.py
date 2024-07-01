from django.shortcuts import render
from rest_framework import generics
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated, IsAdminUser
from .models import History
from .serializers import HistoryListSerializer, HistoryCreateSerializer


class HistoryDetailView(generics.RetrieveAPIView):
    queryset = History.objects.all()
    serializer_class = HistoryListSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        queryset=self.queryset
        return queryset.filter(user=user)


class HistoryListView(generics.ListAPIView):
    queryset = History.objects.all()
    serializer_class = HistoryListSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        queryset=self.queryset
        return queryset.filter(user=user).exclude(is_deleted=True)
    

class HistoryCreateView(generics.CreateAPIView):
    queryset = History.objects.all()
    serializer_class = HistoryCreateSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def perform_create(self, serializer):
        user = self.request.user
        input = serializer.validated_data.get('input')
        output = serializer.validated_data.get('output')
        accuracy = serializer.validated_data.get('accuracy')
        return serializer.save(user=user)
    
