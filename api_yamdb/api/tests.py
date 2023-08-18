"""Тесты для YaMDb API."""
from http import HTTPStatus

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from users import models


def create_user(client, username, email):
    """Shortcut для создания пользователя."""
    url = reverse('signup')
    data = {'username': username,
            'email': email}
    response = client.post(url, data=data)
    return response


def create_user_with_conf_code(client, username, email, conf_code):
    """Shortcut для создания пользователя с заданным кодом подтверждения."""
    response = create_user(client, username, email)
    user = models.YaMDbUser.objects.get(username=username,
                                        email=email)
    user.confirmation_code = conf_code
    user.save()
    return response


def make_client(username: str):
    """Shortcut для создания клиента, который зашел под пользователем user."""
    client = APIClient()
    if username:
        user = get_object_or_404(models.YaMDbUser, username=username)
        confirmation_code = 'A' * settings.CONFIRM_CODE_LEN
        user.confirmation_code = confirmation_code
        user.save()
        auth_data = {
            'username': username,
            'confirmation_code': confirmation_code
        }
        token_response = client.post(reverse('token'), data=auth_data)
        auth_token = token_response.json()['token']
        client.credentials(HTTP_AUTHORIZATION='Bearer ' + auth_token)
    return client


class SignUpTests(TestCase):
    """Тесты для регистрации пользователя."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.guest_client = APIClient()
        cls.url = reverse('signup')

    def test_create_new_user_correct(self):
        data = {'username': 'username_correct',
                'email': 'username_correct@mail.com'}
        items_count = models.YaMDbUser.objects.count()

        response = SignUpTests.guest_client.post(SignUpTests.url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(models.YaMDbUser.objects.count(), items_count + 1)

    def test_create_new_user_correct_fields(self):
        data = {'username': 'username',
                'email': 'username@mail.com'}
        items_count = models.YaMDbUser.objects.count()

        response = SignUpTests.guest_client.post(SignUpTests.url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(models.YaMDbUser.objects.count(), items_count + 1)

        new_user = models.YaMDbUser.objects.get(username=data['username'],
                                                email=data['email'])

        fields = ['username', 'email', 'first_name',
                  'last_name', 'bio', 'role']

        for field_name in fields:
            with self.subTest(f'Field {field_name}'):
                self.assertIn(field_name, dir(new_user))

        self.assertEqual(new_user.role, models.YaMDbUser.Roles.USER)
        self.assertEqual(new_user.groups.count(), 0)
        self.assertEqual(len(new_user.get_all_permissions()), 0)

    def test_create_new_user_missing_data_failed(self):
        data = [{'username': 'username_correct_new'},
                {'email': 'username_correct_new@mail.com'}]
        items_count = models.YaMDbUser.objects.count()

        for subdata in data:
            with self.subTest(f'only {subdata.keys()}'):
                response = SignUpTests.guest_client.post(SignUpTests.url,
                                                         data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
                self.assertEqual(models.YaMDbUser.objects.count(), items_count)

    def test_create_new_user_incorrect_data_failed(self):
        data = [{'username': '',
                'email': 'username_correct_new@mail.com'},
                {'username': 'username_correct_new',
                'email': 'username_correct_new_mail_com'},
                {'username': 'username_correct_new',
                'email': ''}]
        items_count = models.YaMDbUser.objects.count()

        for subdata in data:
            with self.subTest(f'Test data {subdata}'):
                response = SignUpTests.guest_client.post(SignUpTests.url,
                                                         data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
                self.assertEqual(models.YaMDbUser.objects.count(), items_count)

    def test_create_new_user_used_data_failed(self):
        # create new correct user
        data = {'username': 'username_correct_new',
                'email': 'username_correct_new@mail.com'}

        response = SignUpTests.guest_client.post(SignUpTests.url, data=data)
        self.assertEqual(response.status_code, HTTPStatus.OK)

        # try to use already used username or email
        data = [{'username': 'username_correct_new_1',
                'email': 'username_correct_new@mail.com'},
                {'username': 'username_correct_new',
                'email': 'username_correct_new_1@mail.com'}]
        items_count = models.YaMDbUser.objects.count()

        for subdata in data:
            with self.subTest(f'Test data {subdata}'):
                response = SignUpTests.guest_client.post(SignUpTests.url,
                                                         data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
                self.assertEqual(models.YaMDbUser.objects.count(), items_count)

    def test_create_new_user_reserved_username_failed(self):
        data = {'username': 'me',
                'email': 'me@mail.com'}
        items_count = models.YaMDbUser.objects.count()

        response = SignUpTests.guest_client.post(SignUpTests.url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(models.YaMDbUser.objects.count(), items_count)


class RefreshTokenTests(TestCase):
    """Тесты для получения токена."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.guest_client = APIClient()
        cls.url = reverse('token')
        cls.username = 'token_username'
        cls.email = 'token_email@mail.com'
        cls.conf_code = 'AAAAAAAA'
        create_user_with_conf_code(cls.guest_client,
                                   cls.username,
                                   cls.email,
                                   cls.conf_code)

    def test_get_token_correct(self):
        data = {'username': RefreshTokenTests.username,
                'confirmation_code': RefreshTokenTests.conf_code}

        response = RefreshTokenTests.guest_client.post(RefreshTokenTests.url,
                                                       data=data)

        self.assertEqual(response.status_code, HTTPStatus.OK)

        json_response = response.json()
        self.assertIn('token', json_response)

    def test_get_token_missing_data_failed(self):
        data = [{'username': RefreshTokenTests.username},
                {'confirmation_code': RefreshTokenTests.conf_code}]

        for subdata in data:
            with self.subTest(f'only {subdata.keys()}'):
                response = RefreshTokenTests.guest_client.post(
                    RefreshTokenTests.url,
                    data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_get_token_incorrect_data_failed(self):
        data = [{'username': '',
                'confirmation_code': RefreshTokenTests.conf_code},
                {'username': RefreshTokenTests.username,
                'confirmation_code': RefreshTokenTests.conf_code[0:-2]},
                {'username': RefreshTokenTests.username,
                'confirmation_code': ''}]

        for subdata in data:
            with self.subTest(f'Test data {subdata}'):
                response = RefreshTokenTests.guest_client.post(
                    RefreshTokenTests.url,
                    data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_get_token_unknown_user_failed(self):
        data = {'username': RefreshTokenTests.username + "_unknown",
                'confirmation_code': RefreshTokenTests.conf_code}

        response = RefreshTokenTests.guest_client.post(RefreshTokenTests.url,
                                                       data=data)

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)


class GetAllUsersTests(TestCase):
    """Тесты для получения всех пользователей."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = reverse('yamdbuser-list')
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        cls.admins = [
            make_client('superman'),
            make_client('mrsadmin'),
        ]
        cls.others = [
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_get_users_success(self):
        for client in GetAllUsersTests.admins:
            with self.subTest():
                response = client.get(GetAllUsersTests.url)
                self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_get_users_forbidden(self):
        for client in GetAllUsersTests.others:
            with self.subTest():
                response = client.get(GetAllUsersTests.url)
                self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_get_users_guest(self):
        response = GetAllUsersTests.guest.get(GetAllUsersTests.url)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)

    def test_get_users_response_fields(self):
        fields = ['count', 'next', 'previous', 'results']
        client = GetAllUsersTests.admins[0]

        response = client.get(GetAllUsersTests.url)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        json_response = response.json()
        for field in fields:
            self.assertIn(field, json_response)
        self.assertEqual(json_response['count'], 4)

    def test_get_users_search(self):
        client = GetAllUsersTests.admins[0]
        url = GetAllUsersTests.url + '?search=super'

        response = client.get(url)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        json_response = response.json()
        self.assertEqual(json_response['count'], 1)
        self.assertEqual(json_response['results'][0]['username'], 'superman')


class AddUserTests(TestCase):
    """Тесты для создания пользователя администратором."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = reverse('yamdbuser-list')
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        cls.admins = [
            make_client('superman'),
            make_client('mrsadmin'),
        ]
        cls.others = [
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_create_user_success(self):
        for i, client in enumerate(AddUserTests.admins):
            with self.subTest(f'Test {i}'):
                data = {
                    "username": f"success{i}",
                    "email": f"success{i}@example.com",
                    "first_name": "first",
                    "last_name": "last",
                    "bio": "bio",
                    "role": models.YaMDbUser.Roles.USER}
                response = client.post(AddUserTests.url, data=data)
                self.assertEqual(response.status_code, HTTPStatus.CREATED)

    def test_create_user_forbidden(self):
        for i, client in enumerate(AddUserTests.others):
            with self.subTest(f'Test {i}'):
                data = {
                    "username": f"forbidden{i}",
                    "email": f"forbidden{i}@example.com",
                    "first_name": "first",
                    "last_name": "last",
                    "bio": "bio",
                    "role": models.YaMDbUser.Roles.USER}
                response = client.post(AddUserTests.url, data=data)
                self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_create_user_guest(self):
        data = {
            "username": "guest",
            "email": "guest@example.com",
            "first_name": "first",
            "last_name": "last",
            "bio": "bio",
            "role": models.YaMDbUser.Roles.USER}
        response = AddUserTests.guest.post(AddUserTests.url, data=data)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)

    def test_create_user_wrong_data(self):
        client = AddUserTests.admins[0]
        data = [{'username': '',
                'email': 'correct@example.com'},
                {'username': 'me',
                'email': 'me@example.com'},
                {'username': 'correct',
                'email': 'correct_example.com'},
                {'username': 'correct',
                'email': ''}]

        same_data = {"first_name": "first",
                     "last_name": "last",
                     "bio": "bio",
                     "role": models.YaMDbUser.Roles.USER}

        for subdata in data:
            with self.subTest(f'Test data {subdata}'):
                subdata.update(same_data)
                response = client.post(AddUserTests.url, data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_create_user_only_required_data(self):
        client = AddUserTests.admins[0]
        data = {
            "username": "required_data",
            "email": "required_data@example.com"}
        response = client.post(AddUserTests.url, data=data)
        self.assertEqual(response.status_code, HTTPStatus.CREATED)

    def test_create_user_already_exists(self):
        client = AddUserTests.admins[0]
        data = {
            "username": "already_exists",
            "email": "already_exists@example.com"}

        response = client.post(AddUserTests.url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.CREATED)

        data = [{"username": "already_exists",
                 "email": "already_exists@example.com"},
                {"username": "already_exists1",
                 "email": "already_exists@example.com"},
                {"username": "already_exists",
                 "email": "already_exists1@example.com"}]

        for subdata in data:
            with self.subTest(f'Test data {subdata}'):
                response = client.post(AddUserTests.url, data=subdata)
                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_create_user_and_sign_up(self):
        client = AddUserTests.admins[0]
        data = {
            "username": "for_sign_up",
            "email": "for_sign_up@example.com",
            "first_name": "first",
            "last_name": "last",
            "bio": "bio",
            "role": models.YaMDbUser.Roles.USER}
        items_count = models.YaMDbUser.objects.count()

        response = client.post(AddUserTests.url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.CREATED)
        self.assertEqual(models.YaMDbUser.objects.count(), items_count + 1)

        data = {'username': data['username'],
                'email': data['email']}
        items_count = models.YaMDbUser.objects.count()

        signup_url = reverse('signup')
        response = AddUserTests.guest.post(signup_url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(models.YaMDbUser.objects.count(), items_count)

    def test_create_user_response_fields(self):
        client = AddUserTests.admins[0]
        fields = ['username', 'email', 'first_name',
                  'last_name', 'bio', 'role']
        data = {
            "username": "response_fields",
            "email": "response_fields@example.com"}
        items_count = models.YaMDbUser.objects.count()

        response = client.post(AddUserTests.url, data=data)

        self.assertEqual(response.status_code, HTTPStatus.CREATED)
        self.assertEqual(models.YaMDbUser.objects.count(), items_count + 1)

        json_response = response.json()

        for field in fields:
            self.assertIn(field, json_response)

        self.assertEqual(json_response['role'], models.YaMDbUser.Roles.USER)

    def test_create_user_different_roles(self):
        client = AddUserTests.admins[0]
        roles = models.YaMDbUser.Roles.values

        for role in roles:
            with self.subTest(f'Role {role}'):
                data = {
                    "username": f"role_{role}",
                    "email": f"role_{role}@example.com",
                    "role": role}
                response = client.post(AddUserTests.url, data=data)
                self.assertEqual(response.status_code, HTTPStatus.CREATED)
                user = models.YaMDbUser.objects.get(username=data['username'])
                self.assertEqual(user.role, role)


class GetUserTests(TestCase):
    """Тесты для получения пользователя по его имени."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = reverse('yamdbuser-detail', kwargs={'username': 'mrsadmin'})
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        cls.admins = [
            make_client('superman'),
            make_client('mrsadmin'),
        ]
        cls.others = [
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_get_user_success(self):
        for client in GetUserTests.admins:
            with self.subTest():
                response = client.get(GetUserTests.url)
                self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_get_user_forbidden(self):
        for client in GetUserTests.others:
            with self.subTest():
                response = client.get(GetUserTests.url)
                self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_get_user_guest(self):
        response = GetUserTests.guest.get(GetUserTests.url)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)

    def test_get_user_unknown(self):
        client = GetUserTests.admins[0]
        url = reverse('yamdbuser-detail', kwargs={'username': 'david_blaine'})
        response = client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_get_user_response_fields(self):
        client = GetUserTests.admins[0]
        response = client.get(GetUserTests.url)

        fields = ['username', 'email', 'first_name',
                  'last_name', 'bio', 'role']
        json_response = response.json()

        for field_name in fields:
            with self.subTest(f'Field {field_name}'):
                self.assertIn(field_name, json_response)


class DeleteUserTests(TestCase):
    """Тесты для удаления пользователя по его имени."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = reverse('yamdbuser-detail', kwargs={'username': 'victim'})
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        cls.admins = [
            make_client('superman'),
            make_client('mrsadmin'),
        ]
        cls.others = [
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_delete_user_success(self):
        for client in DeleteUserTests.admins:
            with self.subTest():
                models.YaMDbUser.objects.create_user(
                    username='victim',
                    email='victim@mail.com')
                response = client.delete(DeleteUserTests.url)
                self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
                self.assertFalse(
                    models.YaMDbUser.objects.filter(
                        username='victim').exists())

    def test_delete_user_forbidden(self):
        models.YaMDbUser.objects.create_user(
            username='victim',
            email='victim@mail.com')
        for client in DeleteUserTests.others:
            with self.subTest():
                response = client.delete(DeleteUserTests.url)
                self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertTrue(
            models.YaMDbUser.objects.filter(username='victim').exists())
        models.YaMDbUser.objects.filter(username='victim').delete()

    def test_delete_user_guest(self):
        models.YaMDbUser.objects.create_user(
            username='victim',
            email='victim@mail.com')
        response = DeleteUserTests.guest.delete(DeleteUserTests.url)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertTrue(
            models.YaMDbUser.objects.filter(username='victim').exists())

    def test_delete_user_unknown(self):
        client = DeleteUserTests.admins[0]
        url = reverse('yamdbuser-detail', kwargs={'username': 'david_blaine'})
        response = client.delete(url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)


class PatchUserTests(TestCase):
    """Тесты для изменения пользователя по его имени."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        models.YaMDbUser.objects.create_user(
            username='victim',
            email='victim@mail.com')
        cls.admins = [
            make_client('superman'),
            make_client('mrsadmin'),
        ]
        cls.others = [
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_patch_user_success(self):
        last_name = 'victim'
        for i, client in enumerate(PatchUserTests.admins):
            with self.subTest():
                url = reverse('yamdbuser-detail', kwargs={'username':
                                                          last_name})
                new_data = {
                    "username": f"username_{i}",
                    "email": f"user_{i}@example.com",
                    "first_name": f"string {i}",
                    "last_name": f"string {i}",
                    "bio": "string" * i,
                    "role": models.YaMDbUser.Roles.USER}
                response = client.patch(url, data=new_data)
                self.assertEqual(response.status_code, HTTPStatus.OK)
                json_response = response.json()
                for field_name in new_data:
                    self.assertEqual(json_response[field_name],
                                     new_data[field_name])
                last_name = new_data['username']

    def test_patch_user_forbidden(self):
        models.YaMDbUser.objects.create_user(
            username='victim_new',
            email='victim_new@mail.com')
        url = reverse('yamdbuser-detail', kwargs={'username': 'victim_new'})
        for client in PatchUserTests.others:
            with self.subTest():
                new_data = {
                    "username": "username_new",
                    "email": "user_new@example.com",
                    "first_name": "string new",
                    "last_name": "string new",
                    "bio": "string new",
                    "role": models.YaMDbUser.Roles.USER}
                response = client.patch(url, data=new_data)
                self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_patch_user_guest(self):
        models.YaMDbUser.objects.create_user(
            username='victim_guest',
            email='victim_guest@mail.com')
        url = reverse('yamdbuser-detail', kwargs={'username': 'victim_guest'})
        new_data = {
            "username": "username_guest",
            "email": "user_guest@example.com",
            "first_name": "string guest",
            "last_name": "string guest",
            "bio": "string guest",
            "role": models.YaMDbUser.Roles.USER}
        response = PatchUserTests.guest.patch(url, data=new_data)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)

    def test_patch_user_unknown(self):
        client = PatchUserTests.admins[0]
        url = reverse('yamdbuser-detail', kwargs={'username': 'david_blaine'})
        new_data = {
            "username": "username_unknown",
            "email": "user_unknown@example.com",
            "first_name": "string unknown",
            "last_name": "string unknown",
            "bio": "string unknown",
            "role": models.YaMDbUser.Roles.USER}
        response = client.patch(url, data=new_data)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_patch_user_partial(self):
        client = PatchUserTests.admins[0]
        models.YaMDbUser.objects.create_user(
            username='victim_partial',
            email='victim_partial@mail.com')
        url = reverse('yamdbuser-detail', kwargs={'username':
                                                  'victim_partial'})
        new_data = {"role": models.YaMDbUser.Roles.ADMIN}
        response = client.patch(url, data=new_data)

        self.assertEqual(response.status_code, HTTPStatus.OK)


class GetOwnUserTests(TestCase):
    """Тесты для получения своего пользователя."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = reverse('yamdbuser-me')
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        cls.valid_clients = [
            make_client('superman'),
            make_client('mrsadmin'),
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_get_own_user_success(self):
        for client in GetOwnUserTests.valid_clients:
            with self.subTest():
                response = client.get(GetOwnUserTests.url)
                self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_get_own_user_guest(self):
        response = GetOwnUserTests.guest.get(GetOwnUserTests.url)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)

    def test_get_own_user_response_fields(self):
        client = GetOwnUserTests.valid_clients[0]
        response = client.get(GetOwnUserTests.url)

        fields = ['username', 'email', 'first_name',
                  'last_name', 'bio', 'role']
        json_response = response.json()

        for field_name in fields:
            with self.subTest(f'Field {field_name}'):
                self.assertIn(field_name, json_response)


class PatchOwnUserTests(TestCase):
    """Тесты для изменения своего пользователя."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = reverse('yamdbuser-me')
        cls.super_user = models.YaMDbUser.objects.create_superuser(
            username='superman',
            email='superman@mail.com')
        models.YaMDbUser.objects.create_user(
            username='mrsadmin',
            email='mrsadmin@mail.com',
            role=models.YaMDbUser.Roles.ADMIN)
        models.YaMDbUser.objects.create_user(
            username='mrsmoderator',
            email='mrsmoderator@mail.com',
            role=models.YaMDbUser.Roles.MODERATOR)
        models.YaMDbUser.objects.create_user(
            username='mrsuser',
            email='mrsuser@mail.com')
        cls.valid_clients = [
            make_client('superman'),
            make_client('mrsadmin'),
            make_client('mrsmoderator'),
            make_client('mrsuser'),
        ]
        cls.guest = make_client('')

    def test_patch_own_user_success(self):
        for i, client in enumerate(PatchOwnUserTests.valid_clients):
            with self.subTest():
                new_data = {
                    "username": f"username_{i}",
                    "email": f"user_{i}@example.com",
                    "first_name": f"string {i}",
                    "last_name": f"string {i}",
                    "bio": "string" * i}
                response = client.patch(PatchOwnUserTests.url, data=new_data)
                self.assertEqual(response.status_code, HTTPStatus.OK)
                json_response = response.json()
                for field_name in new_data:
                    self.assertEqual(json_response[field_name],
                                     new_data[field_name])

    def test_patch_own_user_guest(self):
        new_data = {
            "username": "username_guest",
            "email": "user_guest@example.com",
            "first_name": "string guest",
            "last_name": "string guest",
            "bio": "string guest"}
        response = PatchOwnUserTests.guest.patch(PatchOwnUserTests.url,
                                                 data=new_data)
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)

    def test_patch_own_user_partial(self):
        client = PatchOwnUserTests.valid_clients[0]
        new_data = {"bio": "A long story."}
        response = client.patch(PatchOwnUserTests.url, data=new_data)

        self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_patch_own_user_change_role(self):
        models.YaMDbUser.objects.create_user(
            username='just_user',
            email='just_user@mail.com')
        client = make_client('just_user')
        new_data = {"role": models.YaMDbUser.Roles.ADMIN}
        response = client.patch(PatchOwnUserTests.url, data=new_data)

        user = models.YaMDbUser.objects.get(username='just_user',
                                            email='just_user@mail.com')
        self.assertEqual(user.role, models.YaMDbUser.Roles.USER)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_patch_own_user_change_username_error(self):
        name = 'just_user_1'
        email = 'just_user_1@mail.com'
        models.YaMDbUser.objects.create_user(
            username=name,
            email=email)
        client = make_client(name)
        new_data = {"username": "me"}
        response = client.patch(PatchOwnUserTests.url, data=new_data)

        user_exists = models.YaMDbUser.objects.filter(username=name,
                                                      email=email).exists()
        self.assertTrue(user_exists)
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
