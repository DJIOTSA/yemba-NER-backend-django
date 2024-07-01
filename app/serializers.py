from rest_framework import serializers
from .models import History

class HistoryListSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="history-detail", lookup_field='pk')
    class Meta:
        model = History
        fields = ['pk', 'url', 'input', 'output', 'accuracy']


class HistoryCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = History
        fields = ['input', 'output', 'user', 'accuracy']