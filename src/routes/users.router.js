import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../utils/prisma/index.js";

const router = express.Router();

router.post('/sign-up', async (req, res, next) => {
    try {
        const { gameId, password, confirmPassword, nickname } = req.body;
        const isExistUser = await prisma.users.findFirst({
            where: {
                gameId,
            },
        });
        if (isExistUser) {
            return res.status(409).json({ message: "이미 존재하는 아이디입니다." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const gameIdRegex = /^[a-z0-9]+$/;

        if (!gameIdRegex.test(gameId)) {
            return res.status(400).json({ message: "아이디는 영어 소문자와 숫자의 조합이어야 합니다." });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: "비밀번호는 최소 6자 이상이어야 합니다." });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ message: "비밀번호와 비밀번호 확인이 일치하지 않습니다." });
        }

        const user = await prisma.users.create({
            data: {
                gameId,
                password: hashedPassword,
                nickname,
            },
        });

        return res.status(201).json({
            userId: user.userId,
            gameId: user.gameId,
            nickname: user.nickname,
        });
    }
    catch (error) {
        console.error('로그인 중 에러 발생:', error);
        return res.status(500).json({ message: ' 로그인 중 에러가 발생하였습니다.' })
    }
});

router.post("/sign-in", async (req, res, next) => {
    try {
        const { gameId, password } = req.body;

        const user = await prisma.users.findFirst({ where: { gameId } });

        if (!user)
            return res.status(401).json({ message: "존재하지 않는 아이디입니다." });
        else if (!(await bcrypt.compare(password, user.password)))
            return res.status(401).json({ message: "비밀번호가 일치하지 않습니다." });

        const token = jwt.sign(
            {
                userId : user.id,
            },
            "jwt-secret"
        );

        res.cookie("authorization", `Bearer ${token}`);
        return res.status(200).json({ message: "로그인 성공"})
    }
    catch (error) {
        console.error('로그인 중 에러 발생:', error);
        return res.status(500).json({ message: ' 로그인 중 에러가 발생하였습니다.' })
    }
})


export default router;