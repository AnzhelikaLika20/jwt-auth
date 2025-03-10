import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(passport.initialize());

const user = {
    username: 'testuser',
    password: bcrypt.hashSync('testpassword', 10),
};

passport.use(new LocalStrategy(
    (username: string, password: string, done: (err: any, user?: any, info?: any) => void) => {
        if (username === user.username && bcrypt.compareSync(password, user.password)) {
            return done(null, user);
        }
        return done(null, false, { message: 'Incorrect username or password' });
    }
));

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'your_secret_key',
};

passport.use(new JWTStrategy(jwtOptions, (jwtPayload: any, done: (err: any, user?: any) => void) => {
    if (jwtPayload.username === user.username) {
        return done(null, user);
    }
    return done(null, false);
}));

app.post('/login', passport.authenticate('local', { session: false }), (req: Request, res: Response) => {
    const token = jwt.sign({ username: user.username }, 'your_secret_key');
    res.json({ token });
});

app.get('/profile', passport.authenticate('jwt', { session: false }), (req: Request, res: Response) => {
    res.json({ message: 'Welcome to your profile!'})})

app.listen(3000, () => {
    console.log('http://localhost:3000');
})
