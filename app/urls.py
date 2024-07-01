from django.urls import path, include
from .views import HistoryCreateView, HistoryDetailView, HistoryListView

urlpatterns = [
    path('history/create/', HistoryCreateView.as_view(), name="history-create"),
    path("history/<int:pk>/", HistoryDetailView.as_view(), name='history-detail'),
    path('history/', HistoryListView.as_view(), name="history-list"),
]
