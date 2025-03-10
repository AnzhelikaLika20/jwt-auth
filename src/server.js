"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const passport_1 = __importDefault(require("passport"));
const passport_local_1 = require("passport-local");
const passport_jwt_1 = require("passport-jwt");
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken")); // Импорт jwt
const app = (0, express_1.default)();
const port = 3000;
// Middleware
app.use(body_parser_1.default.json());
app.use(passport_1.default.initialize());
// Моковый пользователь
const user = {
    username: 'testuser',
    password: bcrypt_1.default.hashSync('testpassword', 10), // Хешированный пароль
};
// Настройка LocalStrategy
passport_1.default.use(new passport_local_1.Strategy((username, password, done) => {
    if (username === user.username && bcrypt_1.default.compareSync(password, user.password)) {
        return done(null, user);
    }
    return done(null, false, { message: 'Incorrect username or password' });
}));
// Настройка JWTStrategy
const jwtOptions = {
    jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'your_secret_key',
};
passport_1.default.use(new passport_jwt_1.Strategy(jwtOptions, (jwtPayload, done) => {
    if (jwtPayload.username === user.username) {
        return done(null, user);
    }
    return done(null, false);
}));
// Эндпоинт для входа и получения JWT
app.post('/login', passport_1.default.authenticate('local', { session: false }), (req, res) => {
    const token = jsonwebtoken_1.default.sign({ username: user.username }, 'your_secret_key');
    res.json({ token });
});
// Защищенный маршрут
app.get('/profile', passport_1.default.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: 'Welcome to your profile!' });
});
