const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');
const cors = require('cors');

const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const port = 3000;

// ─── In-memory хранилища ────────────────────────────────────────────────────
let users = [];
let products = [
    {
        id: nanoid(6),
        title: 'Протеин Gold',
        category: 'Спортпит',
        description: 'Белковая бомба',
        price: 2990
    },
    {
        id: nanoid(6),
        title: 'Креатин Дядя Ваня',
        category: 'Спортпит',
        description: 'Мощная штучка',
        price: 2000
    },
    {
        id: nanoid(6),
        title: 'Штанга',
        category: 'Спорт-инвентарь',
        description: '20 kg',
        price: 1290
    }
];

// ─── Вспомогательные функции ────────────────────────────────────────────────
async function hashPassword(password) {
    return bcrypt.hash(password, 10);
}

async function verifyPassword(password, passwordHash) {
    return bcrypt.compare(password, passwordHash);
}

function findUserOrFail(email, res) {
    const user = users.find(u => u.email === email);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return null;
    }
    return user;
}

function findProductOrFail(id, res) {
    const product = products.find(p => p.id === id);
    if (!product) {
        res.status(404).json({ error: 'Product not found' });
        return null;
    }
    return product;
}

// ─── Swagger ─────────────────────────────────────────────────────────────────
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API спортивного магазина с авторизацией',
            version: '1.0.0',
            description: 'Практическое задание: авторизация + CRUD товаров',
        },
        servers: [{ url: `http://localhost:${port}`, description: 'Локальный сервер' }],
    },
    apis: ['./server.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use((req, res, next) => {
    res.on('finish', () => {
        console.log(`[${new Date().toISOString()}] [${req.method}] ${res.statusCode} ${req.path}`);
        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
            // не логируем пароль в открытом виде
            const safeBody = { ...req.body };
            if (safeBody.password) safeBody.password = '***';
            console.log('Body:', safeBody);
        }
    });
    next();
});

// ════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════

/**
 * @swagger
 * components:
 *   schemas:
 *     RegisterInput:
 *       type: object
 *       required: [email, first_name, last_name, password]
 *       properties:
 *         email:
 *           type: string
 *           example: ivan@example.com
 *         first_name:
 *           type: string
 *           example: Иван
 *         last_name:
 *           type: string
 *           example: Иванов
 *         password:
 *           type: string
 *           example: qwerty123
 *     LoginInput:
 *       type: object
 *       required: [email, password]
 *       properties:
 *         email:
 *           type: string
 *           example: ivan@example.com
 *         password:
 *           type: string
 *           example: qwerty123
 *     Product:
 *       type: object
 *       required: [title, category, description, price]
 *       properties:
 *         id:
 *           type: string
 *         title:
 *           type: string
 *         category:
 *           type: string
 *         description:
 *           type: string
 *         price:
 *           type: number
 */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Регистрация пользователя
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterInput'
 *     responses:
 *       201:
 *         description: Пользователь успешно создан
 *       400:
 *         description: Некорректные данные или email уже занят
 */
app.post('/api/auth/register', async (req, res) => {
    const { email, first_name, last_name, password } = req.body;

    if (!email || !first_name || !last_name || !password) {
        return res.status(400).json({ error: 'email, first_name, last_name and password are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    const newUser = {
        id: nanoid(6),
        email,
        first_name,
        last_name,
        password: await hashPassword(password)
    };

    users.push(newUser);

    // не возвращаем хеш пароля клиенту
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json(userWithoutPassword);
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Вход в систему
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginInput'
 *     responses:
 *       200:
 *         description: Успешный вход
 *       400:
 *         description: Отсутствуют обязательные поля
 *       401:
 *         description: Неверные учётные данные
 *       404:
 *         description: Пользователь не найден
 */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'email and password are required' });
    }

    const user = findUserOrFail(email, res);
    if (!user) return;

    const isAuthenticated = await verifyPassword(password, user.password);
    if (!isAuthenticated) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.status(200).json({ login: true, email: user.email, first_name: user.first_name });
});

// ════════════════════════════════════════════════════════════════════════════
//  PRODUCTS ROUTES
// ════════════════════════════════════════════════════════════════════════════

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Получить список товаров
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Фильтр по категории
 *       - in: query
 *         name: minPrice
 *         schema:
 *           type: number
 *       - in: query
 *         name: maxPrice
 *         schema:
 *           type: number
 *     responses:
 *       200:
 *         description: Список товаров
 */
app.get('/api/products', (req, res) => {
    const { category, minPrice, maxPrice } = req.query;
    let filtered = [...products];

    if (category) {
        filtered = filtered.filter(p => p.category.toLowerCase() === category.toLowerCase());
    }
    if (minPrice) {
        filtered = filtered.filter(p => p.price >= Number(minPrice));
    }
    if (maxPrice) {
        filtered = filtered.filter(p => p.price <= Number(maxPrice));
    }

    res.json(filtered);
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Получить товар по ID
 *     tags: [Products]
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
 *         description: Товар не найден
 */
app.get('/api/products/:id', (req, res) => {
    const product = findProductOrFail(req.params.id, res);
    if (!product) return;
    res.json(product);
});

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Создать товар
 *     tags: [Products]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       201:
 *         description: Товар создан
 *       400:
 *         description: Некорректные данные
 */
app.post('/api/products', (req, res) => {
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
 *     summary: Обновить параметры товара
 *     tags: [Products]
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
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       200:
 *         description: Обновлённый товар
 *       400:
 *         description: Некорректные данные
 *       404:
 *         description: Товар не найден
 */
app.put('/api/products/:id', (req, res) => {
    const product = findProductOrFail(req.params.id, res);
    if (!product) return;

    const { title, category, description, price } = req.body;

    if (!title || !category || !description || price === undefined) {
        return res.status(400).json({ error: 'title, category, description and price are required for full update' });
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
 *     summary: Удалить товар
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Товар удалён
 *       404:
 *         description: Товар не найден
 */
app.delete('/api/products/:id', (req, res) => {
    const index = products.findIndex(p => p.id === req.params.id);
    if (index === -1) {
        return res.status(404).json({ error: 'Product not found' });
    }

    products.splice(index, 1);
    res.status(204).send();
});

// ─── 404 & Error handlers ─────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(port, '127.0.0.1', () => {
    console.log(`Сервер запущен на http://127.0.0.1:${port}`);
    console.log(`Пользователей: ${users.length} | Товаров: ${products.length}`);
    console.log(`Swagger UI: http://127.0.0.1:${port}/api-docs`);
});