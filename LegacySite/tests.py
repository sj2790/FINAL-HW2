from django.test import TestCase, Client
from LegacySite.models import Card
from LegacySite.views import *
from django.urls import reverse
from django.test import TestCase,Client
from django.urls import reverse
import json
from django.core.files.uploadedfile import SimpleUploadedFile
import io
from LegacySite.models import User

# Create your tests here.
class MyTest(TestCase):
    # Django's test run with an empty database. We can populate it with
    # data by using a fixture. You can create the fixture by running:
    #    mkdir LegacySite/fixtures
    #    python manage.py dumpdata LegacySite > LegacySite/fixtures/testdata.json
    # You can read more about fixtures here:
    #    https://docs.djangoproject.com/en/4.0/topics/testing/tools/#fixture-loading
    fixtures = ["testdata.json"]
    # Assuming that your database had at least one Card in it, this
    # test should pass.
    # def test_get_card(self):
    #     allcards = Card.objects.all()
    #     self.assertNotEqual(len(allcards), 0)

    def setUp(self):
        self.client = Client()
        self.csrf_client = Client(enforce_csrf_checks=True)
    
    # ATTACK 1.1: XSS attack(cross-site scripting) vulnerability. 
    def test_xss_bug1(self):
        attack = "<script>alert('hello')</script>"
        attack_para = {'director': attack}
        response = self.client.get('/buy.html', attack_para)
        # compare_Op = "&lt;script&gt;alert(&quot;hello&quot;)&lt;/script&gt;"
        # self.assertIn(compare_Op, response.content.decode("UTF-8"))

    # ATTACK 1.2: XSS attack(cross-site scripting) vulnerability. 
    def test_xss_bug1(self):
        attack2 = "<script>alert('hello')</script>"
        attack_para2 = {'director': attack2}
        response2 = self.client.get('/gift.html', attack_para2)
        # compare_Op = "&lt;script&gt;alert(&quot;hello&quot;)&lt;/script&gt;"
        # self.assertIn(compare_Op, response2.content.decode("UTF-8"))
           
    # ATTACK 2: XSRF attach(cross-site request forgery) vulnerability.   
    def test_xsrf_bug2(self):
        self.client2 = Client(enforce_csrf_checks=True)
        self.client2.login(username='test2', password='test2')
        response = self.client2.post('/gift/0', {'username':'test2','amount':'10000'})
        if response.status_code==302:
            print("XSRF attack was not successfully completed! Forbidden error")

    # ATTACK 3: SQL attack(SQL Injection) vulnerability.   
    def test_sql_bug3(self):
        self.client3 = Client()
        self.client3.login(username='test2', password='test2')
        with open('LegacySite/sqli.gftcrd','rb') as f:
            response = self.client3.post("/use.html", {'card_data': f, 'card_supplied': True, 'card_fname':"sqli.gftcrd",})

        self.assertTrue(response.status_code,200)
        # self.assertContains(response, 'pagination', html=True)
        # self.assertTemplateUsed(response, '/use.html')
        self.assertNotContains(response,'78d2')

    # ATTACK 4: CMD (Command Injection) vulnerability.   
    def test_command_bug4(self):
        client4 = Client()
        client4.login(username='test2', password='test2')
        with open('part1/cmd.gftcrd','rb') as f:
            response = client4.post('/use.html', {'card_data': f, 'card_fname':'appsec & touch abc.txt ;', 'card_supplied':'True'})
        print(response)
        try:
            with open('abc.txt', 'rb') as f:
                raise "Error"
        except:
            pass

    # ATTACK 5: Database Encryption, checking buy card and use card feature.   
    def test_buy_and_use(self):
        client = Client()
        client.login(username='test2', password='test2')
        user = User.objects.get(username='test2')
        response = client.post('/buy/4', {'amount': 1337})
        self.assertEqual(response.status_code, 200)
        # Get the card that was returned
        card = Card.objects.filter(user=user.pk).order_by('-id')[0]
        card_data = response.content
        response = client.post('/use.html',
            {
                'card_supplied': 'True',
                'card_fname': 'Test',
                'card_data': io.BytesIO(card_data),
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Card used!', response.content)
        self.assertTrue(Card.objects.get(pk=card.id).used)