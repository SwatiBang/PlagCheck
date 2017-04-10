from rest_framework import serializers
from models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = VogonUser
        fields = ('username', 'email', 'id', 
                  'full_name')
