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
    



def format_text_with_entities(input_text, entities):
    """ Format input text into html format using defined named entities"""
    import html
    entity_descriptions = {
        'GPE': 'geopolitical location',
        'TIME': 'time',
        'QUAN': 'quantity',
        'GEO': 'geographic location',
        'PER': 'person'
    }
    # Escape HTML special characters in the input text
    input_text = html.escape(input_text)

    # Sort entities by their start position
    entities.sort(key=lambda x: x['start'])

    # Merge sub-words into complete words or phrases and group them by the first entity
    merged_entities = []
    current_entity = None

    for entity in entities:
        if entity['word'].startswith("##"):
            if current_entity is not None:
                current_entity['word'] += entity['word'][2:]
                current_entity['end'] = entity['end']
        else:
            if current_entity is not None:
                merged_entities.append(current_entity)
            current_entity = {
                'entity': entity['entity'],
                'word': entity['word'],
                'start': entity['start'],
                'end': entity['end']
            }

    if current_entity is not None:
        merged_entities.append(current_entity)

    # Group words with the same entity type together
    grouped_entities = []
    current_group = None

    for entity in merged_entities:
        if current_group is None:
            current_group = entity
        elif entity['entity'].startswith('I-') and current_group['entity'].startswith('B-'):
            current_group['word'] += ' ' + entity['word']
            current_group['end'] = entity['end']
        else:
            grouped_entities.append(current_group)
            current_group = entity

    if current_group is not None:
        grouped_entities.append(current_group)

    # Initialize variables
    formatted_text = ""
    last_index = 0

    # Iterate through each grouped entity and format the text
    for entity in grouped_entities:
        start = entity['start']
        end = entity['end']
        entity_text = input_text[start:end]
        # Use the first entity type for the entire group
        entity_type = entity['entity'].split('-')[1]
        entity_description = entity_descriptions.get(
            entity_type, entity_type)  # Get the description

        # Append the text before the entity
        formatted_text += input_text[last_index:start]
        # Format the entity text
        formatted_text += f'<span class="entity {entity_type}">{entity_text} <sub>({entity_description})</sub></span>'
        # Update the last index
        last_index = end

    # Append the remaining text after the last entity
    formatted_text += input_text[last_index:]

    return formatted_text


    
