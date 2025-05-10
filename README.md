# **Система управления контрагентами**

Система управления контрагентами - это веб-приложение, разработанное для эффективного управления и мониторинга взаимодействий с контрагентами. Система позволяет создавать, редактировать и отслеживать информацию о контрагентах, управлять договорами и документами, а также анализировать историю взаимодействий.

## **Структура репозиториев**

Проект разделен на три отдельных репозитория:

1. [contragent-work-client](https://github.com/your-username/contragent-work-client) - Клиентская часть приложения
2. [contragent-work-server](https://github.com/your-username/contragent-work-server) - Серверная часть приложения
3. [contragent-work-docs](https://github.com/your-username/contragent-work-docs) - Документация проекта (текущий репозиторий)

---

## **Содержание**

1. [Архитектура](#архитектура)
    1. [C4-модель](#c4-модель)
    2. [Схема данных](#схема-данных)
2. [Функциональные возможности](#функциональные-возможности)
    1. [Диаграмма вариантов использования](#диаграмма-вариантов-использования)
    2. [User-flow диаграммы](#user-flow-диаграммы)
3. [Детали реализации](#детали-реализации)
    1. [UML-диаграммы](#uml-диаграммы)
    2. [Спецификация API](#спецификация-api)
    3. [Безопасность](#безопасность)
    4. [Оценка качества кода](#оценка-качества-кода)
4. [Тестирование](#тестирование)
    1. [Unit-тесты](#unit-тесты)
    2. [Интеграционные тесты](#интеграционные-тесты)
5. [Установка и запуск](#установка-и-запуск)
    1. [Манифесты для сборки docker образов](#манифесты-для-сборки-docker-образов)
    2. [Манифесты для развертывания k8s кластера](#манифесты-для-развертывания-k8s-кластера)
6. [Лицензия](#лицензия)
7. [Контакты](#контакты)

---

## **Архитектура**

### C4-модель

![C4-модель системы](images/C4.png)

### Схема данных

![База данных](images/БД.png)

---

## **Функциональные возможности**

### Диаграмма вариантов использования

![Use case](images/UseCase.png)

### User-flow диаграммы

![User Flow](images/UF1.png)
![User Flow](images/UF2.png)
![User Flow](images/UF3.png)

---

## **Детали реализации**

### UML-диаграммы

![Диаграмма классов](images/Class.png)
![Диаграмма компонентов](images/Components.png)
![Диаграмма последовательности](images/Placements.png)
![Диаграмма размещения](images/Sequence.png)

### Спецификация API

#### Основные API эндпоинты

1. `/api/check.php`
   - **Метод**: POST
   - **Описание**: Проверка контрагента по УНП
   - **Параметры запроса**: JSON с полем `unp` (УНП контрагента)
   - **Ответ**: Информация о компании, статус проверки, рейтинг надежности

2. `/api/reports.php`
   - **Методы**: GET, DELETE
   - **Описание**: Получение списка отчетов или удаление отчета
   - **Параметры GET**: `id` (опционально), `limit`, `offset`, `search`
   - **Параметры DELETE**: `id` (обязательно)
   - **Ответ**: Список отчетов или статус удаления

3. `/api/export_pdf.php`
   - **Метод**: POST
   - **Описание**: Экспорт отчета в формат PDF
   - **Параметры запроса**: JSON с полем `report_id` или `unp`
   - **Ответ**: PDF-файл с отчетом о проверке контрагента

#### Сервис аутентификации (/services/auth/api/)

1. `/login.php`
   - **Метод**: POST
   - **Описание**: Аутентификация пользователей
   - **Параметры запроса**: JSON с полями `username` и `password`
   - **Ответ**: Токены доступа и обновления, информация о пользователе

2. `/refresh-token.php`
   - **Метод**: POST
   - **Описание**: Обновление токена доступа
   - **Параметры запроса**: JSON с полем `refresh_token`
   - **Ответ**: Новые токены доступа и обновления

3. `/validate-token.php`
   - **Методы**: GET, POST
   - **Описание**: Проверка действительности токена
   - **Параметры**: Токен в заголовке Authorization
   - **Ответ**: Статус валидации и информация о пользователе

#### Управление пользователями (/services/auth/api/users/)

1. `/index.php`
   - **Методы**: GET, POST
   - **Описание**: Получение списка всех пользователей или создание нового пользователя
   - **Ответ GET**: Список пользователей
   - **Параметры POST**: Данные нового пользователя

2. `/user.php`
   - **Методы**: GET, PUT, DELETE
   - **Описание**: Получение, обновление или удаление пользователя
   - **Параметры**: `id` (идентификатор пользователя)
   - **Ответ**: Данные пользователя или статус операции

#### Управление ролями (/services/auth/api/roles/)

1. `/index.php`
   - **Методы**: GET, POST
   - **Описание**: Получение списка всех ролей или создание новой роли
   - **Ответ GET**: Список ролей
   - **Параметры POST**: Данные новой роли

2. `/role.php`
   - **Методы**: GET, PUT, DELETE
   - **Описание**: Получение, обновление или удаление роли
   - **Параметры**: `id` (идентификатор роли)
   - **Ответ**: Данные роли или статус операции

Все API-эндпоинты возвращают данные в формате JSON, за исключением `/api/export_pdf.php`, который возвращает PDF-файл. Для доступа к защищенным эндпоинтам требуется передача JWT-токена в заголовке Authorization.

### Безопасность

В проекте реализованы комплексные меры безопасности для защиты данных и обеспечения корректного доступа к ресурсам системы.

#### Аутентификация

Система использует JWT (JSON Web Tokens) для аутентификации пользователей. Этот подход обеспечивает безопасную и stateless аутентификацию.

```php
// Фрагмент кода из JwtUtil.php
public static function generateToken($userData) {
    $issuedAt = time();
    $expirationTime = $issuedAt + self::TOKEN_EXPIRATION;
    
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'data' => [
            'id' => $userData['id'],
            'username' => $userData['username'],
            'email' => $userData['email'] ?? null,
            'role' => $userData['role_name']
        ]
    ];
    
    return self::encode($payload);
}

public static function validateToken($token) {
    try {
        $decoded = self::decode($token);
        
        // Проверка срока действия
        if ($decoded['exp'] < time()) {
            return false;
        }
        
        return $decoded['data'];
    } catch (Exception $e) {
        return false;
    }
}
```

#### Авторизация

Авторизация основана на ролевой модели, которая определяет права доступа к различным функциям системы.

```php
// Фрагмент кода из api/reports.php
// Проверка ролей (доступ только для администратора и аналитика)
if ($user['role'] !== 'administrator' && $user['role'] !== 'analyst') {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Доступ запрещен']);
    exit;
}
```

#### Защита от уязвимостей

1. **Защита от инъекций SQL**

Все запросы к базе данных выполняются с использованием подготовленных выражений (prepared statements), что предотвращает SQL-инъекции.

```php
// Пример защиты от SQL-инъекций
$sql = "SELECT * FROM users WHERE username = :username";
$stmt = $db->prepare($sql);
$stmt->execute([':username' => $username]);
```

2. **Защита от CSRF (Cross-Site Request Forgery)**

Использование JWT в заголовках запросов вместо cookie обеспечивает защиту от CSRF-атак.

#### Безопасное хранение данных

Пароли пользователей хранятся в базе данных в виде хешей, созданных с использованием алгоритма bcrypt.

```php
// Пример хеширования пароля
$hashedPassword = password_hash($plainTextPassword, PASSWORD_BCRYPT, ['cost' => 12]);

// Проверка пароля
$isValid = password_verify($inputPassword, $hashedPasswordFromDb);
```

#### Шифрование данных при передаче

Все коммуникации между клиентом и сервером осуществляются через HTTPS, что обеспечивает шифрование данных при передаче.

## **Тестирование**

### Unit-тесты

Unit-тесты
require_once 'path/to/tests/bootstrap.php';
require_once 'path/to/src/utils/JwtUtil.php';

class JwtUtilTest extends PHPUnit\Framework\TestCase {
    private $testUser;

    protected function setUp(): void {
        $this->testUser = [
            'id' => 1,
            'username' => 'testuser',
            'email' => 'test@example.com',
            'role_name' => 'user'
        ];
    }

    public function testGenerateToken() {
        $token = JwtUtil::generateToken($this->testUser);
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/', $token);
    }

    public function testValidateValidToken() {
        $token = JwtUtil::generateToken($this->testUser);
        $userData = JwtUtil::validateToken($token);
        $this->assertEquals($this->testUser['id'], $userData['id']);
        $this->assertEquals($this->testUser['username'], $userData['username']);
        $this->assertEquals($this->testUser['email'], $userData['email']);
        $this->assertEquals($this->testUser['role_name'], $userData['role']);
    }

    public function testValidateExpiredToken() {
        $reflector = new ReflectionClass('JwtUtil');
        $encodeMethod = $reflector->getMethod('encode');
        $encodeMethod->setAccessible(true);

        $payload = [
            'iat' => time() - 3600,
            'exp' => time() - 1800, // Токен истек 30 минут назад
            'data' => [
                'id' => $this->testUser['id'],
                'username' => $this->testUser['username'],
                'email' => $this->testUser['email'],
                'role' => $this->testUser['role_name']
            ]
        ];

        $token = $encodeMethod->invokeArgs(null, [$payload]);
        $this->assertFalse(JwtUtil::validateToken($token));
    }

    public function testValidateInvalidToken() {
        $this->assertFalse(JwtUtil::validateToken('invalid.token.string'));
    }
}



require_once 'path/to/tests/bootstrap.php';
require_once 'path/to/src/controllers/AuthController.php';

class AuthControllerTest extends PHPUnit\Framework\TestCase {
    private $authController;
    private $mockUserModel;

    protected function setUp(): void {
        $this->mockUserModel = $this->createMock(User::class);
        $this->authController = new class($this->mockUserModel) extends AuthController {
            private $userModel;
            public function __construct($userModel) {
                $this->userModel = $userModel;
            }
            protected function getUserModel() {
                return $this->userModel;
            }
        };
    }

    public function testLoginInvalidCredentials() {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['username'] = 'testuser';
        $_POST['password'] = 'wrongpassword';

        $this->mockUserModel->expects($this->once())
            ->method('validateCredentials')
            ->with('testuser', 'wrongpassword')
            ->willReturn(false);

        $this->expectOutputRegex('/"status":"error"/');
        $this->authController->login();
    }

    public function testValidateTokenSuccess() {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer valid.token.here';

        JwtUtil::staticExpects($this->once())
            ->method('validateToken')
            ->with('valid.token.here')
            ->willReturn([
                'id' => 1,
                'username' => 'testuser',
                'email' => 'test@example.com',
                'role' => 'user'
            ]);

        ob_start();
        $this->authController->validateToken();
        $output = ob_get_clean();

        $response = json_decode($output, true);
        $this->assertEquals('success', $response['status']);
        $this->assertArrayHasKey('user', $response['data']);
    }
}

### Интеграционные тесты

Интеграционные тесты

require_once 'path/to/tests/bootstrap.php';

class ApiAuthTest extends PHPUnit\Framework\TestCase {
    private $baseUrl = 'http://localhost/contragent_work/services/auth/api';

    public function testLoginEndpoint() {
        $userData = [
            'username' => 'testuser',
            'password' => 'password123'
        ];

        $response = $this->performHttpRequest($this->baseUrl . '/login.php', 'POST', $userData);
        $this->assertEquals(200, $response['status']);
        $data = json_decode($response['body'], true);
        $this->assertEquals('success', $data['status']);
        $this->assertArrayHasKey('token', $data['data']);
    }

    public function testValidateTokenEndpoint() {
        $userData = [
            'username' => 'testuser',
            'password' => 'password123'
        ];
        $loginResponse = $this->performHttpRequest($this->baseUrl . '/login.php', 'POST', $userData);
        $loginData = json_decode($loginResponse['body'], true);
        $token = $loginData['data']['token'];

        $response = $this->performHttpRequest(
            $this->baseUrl . '/validate-token.php',
            'GET',
            null,
            ['Authorization' => 'Bearer ' . $token]
        );

        $this->assertEquals(200, $response['status']);
        $data = json_decode($response['body'], true);
        $this->assertEquals('success', $data['status']);
        $this->assertArrayHasKey('user', $data['data']);
    }

    private function performHttpRequest($url, $method, $data = null, $headers = []) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($data) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                $headers['Content-Type'] = 'application/json';
            }
        }

        if (!empty($headers)) {
            $curlHeaders = [];
            foreach ($headers as $key => $value) {
                $curlHeaders[] = "$key: $value";
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
        }

        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [
            'status' => $status,
            'body' => $body
        ];
    }
}

require_once 'path/to/tests/bootstrap.php';

class ApiSecurityTest extends PHPUnit\Framework\TestCase {
    private $baseUrl = 'http://localhost/contragent_work/api';

    public function testProtectedEndpointWithoutToken() {
        $response = $this->performHttpRequest($this->baseUrl . '/users/index.php', 'GET');
        $this->assertEquals(401, $response['status']);
        $data = json_decode($response['body'], true);
        $this->assertEquals('error', $data['status']);
        $this->assertStringContainsString('Token', $data['message']);
    }

    public function testXssProtection() {
        $xssPayload = '<script>alert("XSS");</script>';
        $userData = [
            'username' => $xssPayload,
            'password' => 'password123'
        ];

        $response = $this->performHttpRequest(
            $this->baseUrl . '/auth/login.php',
            'POST',
            $userData
        );

        $this->assertNotEquals(200, $response['status']);
        $this->assertStringNotContainsString($xssPayload, $response['body']);
    }
}

---


## **Лицензия**

Этот проект лицензирован по лицензии MIT - подробности представлены в файле [LICENSE.md](LICENSE.md)

---

## **Контакты**

Автор: golovachnastya9@gmail.com 
