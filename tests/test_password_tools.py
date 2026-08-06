from tests.base import AppTestCase


class PasswordGeneratorTests(AppTestCase):
    def test_generator_is_browser_only_and_checker_is_removed(self):
        self.create_user()
        self.login()

        response = self.client.get("/password/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Browser-only", response.data)
        self.assertNotIn(b"Password Strength Checker", response.data)
        self.assertNotIn(b'name="password"', response.data)

        self.assertEqual(self.client.post("/password/check").status_code, 404)
        self.assertEqual(self.client.post("/password/generate").status_code, 404)
