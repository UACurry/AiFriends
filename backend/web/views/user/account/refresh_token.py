from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken


class RefreshTokenView(APIView):
    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            if not refresh_token:
                return Response({
                    'result': 'refresh token不存在'
                }, status=401)  # 必须加401
            refresh = RefreshToken(refresh_token)  # 自动检验 如果refresh token过期了，会报异常
            # 如果没有过期
            if settings.SIMPLE_JWT['ROTATE_REFRESH_TOKENS']: # refresh 刷新access 的时候，会刷新 refresh。
                refresh.set_jti() # 刷新refresh
                response = Response({
                    'result': 'success',
                    'access': str(refresh.access_token),
                })
                response.set_cookie(
                    key='refresh_token',
                    value=str(refresh),
                    httponly=True,
                    samesite='Lax',
                    secure=True,
                    max_age=86400 * 7,
                )
                return response
            return Response({
                'result': 'success',
                'access': str(refresh.access_token),
            })
        except:
            return Response({
                'result': "refresh token过期了"
            }, status=401)  # 必须加401
