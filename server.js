const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const port = 3000;

const ACCESS_SECRET = 'access_secret';
const REFRESH_SECRET = 'refresh_secret';
const ACCESS_EXPIRES_IN = '15m';
const REFRESH_EXPIRES_IN = '7d';

// ─── In-memory хранилища ────────────────────────────────────────────────────
let users = [];
let products = [
    { id: nanoid(6), title: 'Протеин Gold', category: 'Спортпит', description: 'Белковая бомба', price: 2990 },
    { id: nanoid(6), title: 'Креатин Дядя Ваня', category: 'Спортпит', description: 'Мощная штучка', price: 2000 },
    { id: nanoid(6), title: 'Штанга', category: 'Спорт-инвентарь', description: '20 kg', price: 1290 }
];
const refreshTokens = new Set();

// ─── Генерация токенов ───────────────────────────────────────────────────────
function generateAccessToken(user) {
    return jwt.sign(
        { sub: user.id, email: user.email, first_name: user.first_name, role: user.role },
        ACCESS_SECRET,
        { expiresIn: ACCESS_EXPIRES_IN }
    );
}

function generateRefreshToken(user) {
    return jwt.sign(
        { sub: user.id, email: user.email, role: user.role },
        REFRESH_SECRET,
        { expiresIn: REFRESH_EXPIRES_IN }
    );
}

// ─── Вспомогательные функции ─────────────────────────────────────────────────
async function hashPassword(password) {
    return bcrypt.hash(password, 10);
}

async function verifyPassword(password, passwordHash) {
    return bcrypt.compare(password, passwordHash);
}

function findProductOrFail(id, res) {
    const product = products.find(p => p.id === id);
    if (!product) { res.status(404).json({ error: 'Product not found' }); return null; }
    return product;
}

// ─── Middleware ───────────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }
    try {
        req.user = jwt.verify(token, ACCESS_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function roleMiddleware(allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
}

// ─── Swagger ──────────────────────────────────────────────────────────────────
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: { title: 'Sport Shop API с RBAC', version: '4.0.0', description: 'Практика 11' },
        servers: [{ url: `http://localhost:${port}` }],
        components: {
            securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }
        }
    },
    apis: ['./server.js'],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);

app.use(cors());
app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use((req, res, next) => {
    res.on('finish', () => {
        console.log(`[${new Date().toISOString()}] [${req.method}] ${res.statusCode} ${req.path}`);
    });
    next();
});

// ════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES (Гость)
// ════════════════════════════════════════════════════════════════════════════

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Регистрация (Гость)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, first_name, last_name, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: ivan@example.com
 *               first_name:
 *                 type: string
 *                 example: Иван
 *               last_name:
 *                 type: string
 *                 example: Иванов
 *               password:
 *                 type: string
 *                 example: qwerty123
 *               role:
 *                 type: string
 *                 enum: [user, seller, admin]
 *                 example: user
 *     responses:
 *       201:
 *         description: Пользователь создан
 *       400:
 *         description: Ошибка валидации
 */
app.post('/api/auth/register', async (req, res) => {
    const { email, first_name, last_name, password, role } = req.body;

    if (!email || !first_name || !last_name || !password) {
        return res.status(400).json({ error: 'email, first_name, last_name and password are required' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    const allowedRoles = ['user', 'seller', 'admin'];
    const assignedRole = allowedRoles.includes(role) ? role : 'user';

    const newUser = {
        id: nanoid(6),
        email,
        first_name,
        last_name,
        password: await hashPassword(password),
        role: assignedRole,
        blocked: false
    };

    users.push(newUser);
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Вход в систему (Гость)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Пара токенов
 *       401:
 *         description: Неверные данные
 */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'email and password are required' });
    }

    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.blocked) return res.status(403).json({ error: 'User is blocked' });

    if (!(await verifyPassword(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.add(refreshToken);

    res.status(200).json({ accessToken, refreshToken });
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Обновление токенов (Гость)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Новая пара токенов
 *       401:
 *         description: Невалидный токен
 */
app.post('/api/auth/refresh', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken is required' });
    if (!refreshTokens.has(refreshToken)) return res.status(401).json({ error: 'Invalid refresh token' });

    try {
        const payload = jwt.verify(refreshToken, REFRESH_SECRET);
        const user = users.find(u => u.id === payload.sub);
        if (!user) return res.status(401).json({ error: 'User not found' });

        refreshTokens.delete(refreshToken);
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);
        refreshTokens.add(newRefreshToken);

        res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    } catch {
        return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Текущий пользователь (🔒 Пользователь+)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Объект пользователя
 *       401:
 *         description: Не авторизован
 */
app.get('/api/auth/me', authMiddleware, (req, res) => {
    const user = users.find(u => u.id === req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password: _, ...safe } = user;
    res.json(safe);
});

// ════════════════════════════════════════════════════════════════════════════
//  USERS ROUTES (Администратор)
// ════════════════════════════════════════════════════════════════════════════

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Список пользователей (🔒 Администратор)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Список пользователей
 *       403:
 *         description: Нет доступа
 */
app.get('/api/users', authMiddleware, roleMiddleware(['admin']), (req, res) => {
    const safeUsers = users.map(({ password: _, ...u }) => u);
    res.json(safeUsers);
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Пользователь по ID (🔒 Администратор)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Данные пользователя
 *       404:
 *         description: Не найден
 */
app.get('/api/users/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password: _, ...safe } = user;
    res.json(safe);
});

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Обновить пользователя (🔒 Администратор)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [user, seller, admin]
 *     responses:
 *       200:
 *         description: Обновлённый пользователь
 *       404:
 *         description: Не найден
 */
app.put('/api/users/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { first_name, last_name, role } = req.body;
    const allowedRoles = ['user', 'seller', 'admin'];

    if (first_name) user.first_name = first_name;
    if (last_name) user.last_name = last_name;
    if (role && allowedRoles.includes(role)) user.role = role;

    const { password: _, ...safe } = user;
    res.json(safe);
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Заблокировать пользователя (🔒 Администратор)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Пользователь заблокирован
 *       404:
 *         description: Не найден
 */
app.delete('/api/users/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.blocked = true;
    res.json({ message: 'User blocked', id: user.id });
});

// ════════════════════════════════════════════════════════════════════════════
//  PRODUCTS ROUTES
// ════════════════════════════════════════════════════════════════════════════

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Список товаров (🔒 Пользователь+)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Список товаров
 */
app.get('/api/products', authMiddleware, roleMiddleware(['user', 'seller', 'admin']), (req, res) => {
    const { category, minPrice, maxPrice } = req.query;
    let filtered = [...products];
    if (category) filtered = filtered.filter(p => p.category.toLowerCase() === category.toLowerCase());
    if (minPrice) filtered = filtered.filter(p => p.price >= Number(minPrice));
    if (maxPrice) filtered = filtered.filter(p => p.price <= Number(maxPrice));
    res.json(filtered);
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Товар по ID (🔒 Пользователь+)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Данные товара
 *       404:
 *         description: Не найден
 */
app.get('/api/products/:id', authMiddleware, roleMiddleware(['user', 'seller', 'admin']), (req, res) => {
    const product = findProductOrFail(req.params.id, res);
    if (!product) return;
    res.json(product);
});

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Создать товар (🔒 Продавец, Администратор)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title, category, description, price]
 *             properties:
 *               title:
 *                 type: string
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *     responses:
 *       201:
 *         description: Товар создан
 *       403:
 *         description: Нет доступа
 */
app.post('/api/products', authMiddleware, roleMiddleware(['seller', 'admin']), (req, res) => {
    const { title, category, description, price } = req.body;
    if (!title || !category || !description || price === undefined) {
        return res.status(400).json({ error: 'title, category, description and price are required' });
    }
    if (isNaN(Number(price)) || Number(price) < 0) {
        return res.status(400).json({ error: 'price must be a non-negative number' });
    }
    const newProduct = {
        id: nanoid(6),
        title: title.trim(),
        category: category.trim(),
        description: description.trim(),
        price: Number(price)
    };
    products.push(newProduct);
    res.status(201).json(newProduct);
});

/**
 * @swagger
 * /api/products/{id}:
 *   put:
 *     summary: Обновить товар (🔒 Продавец, Администратор)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title, category, description, price]
 *             properties:
 *               title:
 *                 type: string
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *     responses:
 *       200:
 *         description: Обновлённый товар
 *       403:
 *         description: Нет доступа
 *       404:
 *         description: Не найден
 */
app.put('/api/products/:id', authMiddleware, roleMiddleware(['seller', 'admin']), (req, res) => {
    const product = findProductOrFail(req.params.id, res);
    if (!product) return;
    const { title, category, description, price } = req.body;
    if (!title || !category || !description || price === undefined) {
        return res.status(400).json({ error: 'title, category, description and price are required' });
    }
    if (isNaN(Number(price)) || Number(price) < 0) {
        return res.status(400).json({ error: 'price must be a non-negative number' });
    }
    product.title = title.trim();
    product.category = category.trim();
    product.description = description.trim();
    product.price = Number(price);
    res.json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   delete:
 *     summary: Удалить товар (🔒 Администратор)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Удалён
 *       403:
 *         description: Нет доступа
 *       404:
 *         description: Не найден
 */
app.delete('/api/products/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
    const index = products.findIndex(p => p.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Product not found' });
    products.splice(index, 1);
    res.status(204).send();
});

// ─── 404 & Error handlers ─────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(port, '127.0.0.1', () => {
    console.log(`Сервер запущен на http://127.0.0.1:${port}`);
    console.log(`Товаров: ${products.length}`);
    console.log(`Swagger UI: http://127.0.0.1:${port}/api-docs`);
});