import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { GoogleGenerativeAI } from '@google/generative-ai';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "http://localhost:3000",
  }
});

const prisma = new PrismaClient();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');
const GEMINI_MODEL_ID = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
const model = genAI.getGenerativeModel({
  model: GEMINI_MODEL_ID,
  generationConfig: {
    temperature: 0.9,
    topK: 1,
    topP: 1,
    maxOutputTokens: 2048,
  },
});

app.use(helmet());
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

const getClientIP = (req: any): string => {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['x-real-ip'] || 
         req.socket.remoteAddress || 
         'unknown';
};

const hashIP = (ip: string): string => {
  return bcrypt.hashSync(ip, 10);
};

const checkIPHash = (ip: string, hash: string): boolean => {
  try {
    return bcrypt.compareSync(ip, hash);
  } catch (e) {
    return false;
  }
};

const checkIPBan = async (req: any, res: any, next: any) => {
  const ip = getClientIP(req);
  
  try {
    const bannedIPs = await prisma.bannedIP.findMany();
    
    for (const banned of bannedIPs) {
      if (checkIPHash(ip, banned.ipAddress)) {
        return res.status(403).json({ error: 'Twój adres IP został zablokowany' });
      }
    }
    
    next();
  } catch (e) {
    next();
  }
};

const authenticateToken = async (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('❌ No token provided');
    return res.sendStatus(401);
  }

  try {
    const decoded: any = jwt.verify(token, JWT_SECRET) as any;
    if (!decoded || !decoded.id) {
      console.log('❌ Invalid token payload');
      return res.sendStatus(403);
    }

    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user) {
      console.log('❌ User not found for token');
      return res.sendStatus(401);
    }
    if (user.isBanned) {
      console.log('❌ User is banned');
      return res.status(403).json({ error: 'Konto zostało zablokowane' });
    }

    req.user = { id: user.id, isAdmin: user.isAdmin };
    next();
  } catch (err: any) {
    console.log('❌ Token verification failed:', err.message);
    return res.sendStatus(403);
  }
};

app.post('/api/auth/anonymous', checkIPBan, async (req, res) => {
  const { nickname } = req.body;
  const ip = getClientIP(req);

  if (!nickname || typeof nickname !== 'string') {
    return res.status(400).json({ error: 'Nickname is required' });
  }

  try {
    const existingUser = await prisma.user.findFirst({ where: { nickname } });
    if (existingUser) {
      return res.status(400).json({ error: 'Nickname already taken' });
    }

    const user = await prisma.user.create({
      data: {
        nickname: nickname,
        isBanned: false,
        lastIpAddress: hashIP(ip),
      },
    });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    console.error('Error creating anonymous user:', error);
    res.status(500).json({ error: 'Failed to create anonymous user' });
  }
});

app.post('/api/mood', authenticateToken, async (req, res) => {
  const { mood, note } = req.body;
  const userId = (req as any).user.id;

  if (mood < 1 || mood > 5) {
    return res.status(400).json({ error: 'Mood must be between 1 and 5' });
  }

  try {
    const moodEntry = await prisma.moodEntry.create({
      data: {
        userId,
        mood,
        note: note || null,
      },
    });

    res.json(moodEntry);
  } catch (e) {
    res.status(500).json({ error: 'Could not save mood entry' });
  }
});

app.get('/api/mood', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;

  try {
    const moods = await prisma.moodEntry.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 20,
    });

    res.json(moods);
  } catch (e) {
    res.status(500).json({ error: 'Could not retrieve mood entries' });
  }
});

app.delete('/api/mood/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = (req as any).user.id;

  try {
    const moodEntry = await prisma.moodEntry.findUnique({
      where: { id },
    });

    if (!moodEntry) {
      return res.status(404).json({ error: 'Wpis nie istnieje' });
    }

    if (moodEntry.userId !== userId) {
      return res.status(403).json({ error: 'Nie możesz usunąć cudzego wpisu' });
    }

    await prisma.moodEntry.delete({
      where: { id },
    });

    res.json({ success: true });
  } catch (e) {
    console.error('Error deleting mood entry:', e);
    res.status(500).json({ error: 'Could not delete mood entry' });
  }
});

const SALT_ROUNDS = 10;

const hashPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, SALT_ROUNDS);
};

const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};

app.post('/api/auth/register', checkIPBan, async (req, res) => {
  const { nickname, password } = req.body;
  const ip = getClientIP(req);

  if (!nickname || !password) {
    return res.status(400).json({ error: 'Nickname and password are required' });
  }

  try {
    const existingNickname = await prisma.user.findFirst({ where: { nickname } });
    if (existingNickname) {
      return res.status(400).json({ error: 'Nickname already taken' });
    }

    const hashedPassword = await hashPassword(password);

    const user = await prisma.user.create({
      data: {
        nickname,
        passwordHash: hashedPassword,
        lastIpAddress: hashIP(ip),
      },
    });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });

    res.json({ token, user: { id: user.id, nickname: user.nickname } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not register user' });
  }
});

app.post('/api/auth/login', checkIPBan, async (req, res) => {
  const { nickname, password, twoFactorCode } = req.body;
  const ip = getClientIP(req);

  if (!nickname || !password) {
    return res.status(400).json({ error: 'Nickname and password are required' });
  }

  try {
    const user = await prisma.user.findFirst({
      where: { nickname },
      select: {
        id: true,
        nickname: true,
        passwordHash: true,
        isBanned: true,
        twoFactorEnabled: true as any,
        twoFactorSecret: true as any,
      }
    }) as any;

    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: 'Invalid nickname or password' });
    }

    if (user.isBanned) {
      return res.status(403).json({ error: 'Jesteś zbanowany' });
    }

    const isPasswordValid = await comparePassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid nickname or password' });
    }

    if (user.twoFactorEnabled && user.twoFactorSecret) {
      if (!twoFactorCode) {
        return res.status(200).json({ 
          requires2FA: true,
          message: 'Kod weryfikacji dwuetapowej jest wymagany' 
        });
      }

      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 2
      });

      if (!verified) {
        return res.status(401).json({ error: 'Nieprawidłowy kod weryfikacji' });
      }
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { 
        lastSeen: new Date(),
        lastIpAddress: hashIP(ip),
      },
    });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });

    res.json({ token, user: { id: user.id, nickname: user.nickname } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not log in' });
  }
});


app.post('/api/2fa/setup', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      select: { id: true, nickname: true, passwordHash: true, twoFactorEnabled: true as any }
    }) as any;
    
    if (!user || !user.passwordHash) {
      return res.status(400).json({ error: 'Weryfikacja dwuetapowa dostępna tylko dla zarejestrowanych kont' });
    }
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: 'Weryfikacja dwuetapowa jest już włączona' });
    }
    
    const secret = speakeasy.generateSecret({
      name: `HelpForMind (${user.nickname})`,
      issuer: 'HelpForMind'
    });
    
    const qrCode = await QRCode.toDataURL(secret.otpauth_url || '');
    
    res.json({
      secret: secret.base32,
      qrCode: qrCode
    });
  } catch (error) {
    console.error('Error generating 2FA secret:', error);
    res.status(500).json({ error: 'Nie udało się wygenerować konfiguracji 2FA' });
  }
});

app.post('/api/2fa/enable', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { secret, code } = req.body;
  
  if (!secret || !code) {
    return res.status(400).json({ error: 'Sekret i kod są wymagane' });
  }
  
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      select: { id: true, passwordHash: true, twoFactorEnabled: true as any }
    }) as any;
    
    if (!user || !user.passwordHash) {
      return res.status(400).json({ error: 'Weryfikacja dwuetapowa dostępna tylko dla zarejestrowanych kont' });
    }
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: 'Weryfikacja dwuetapowa jest już włączona' });
    }
    
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 2
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Nieprawidłowy kod weryfikacji' });
    }
    
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret,
        twoFactorEnabled: true
      } as any
    });
    
    res.json({ message: 'Weryfikacja dwuetapowa została włączona' });
  } catch (error) {
    console.error('Error enabling 2FA:', error);
    res.status(500).json({ error: 'Nie udało się włączyć weryfikacji dwuetapowej' });
  }
});

app.post('/api/2fa/disable', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { password, code } = req.body;
  
  if (!password || !code) {
    return res.status(400).json({ error: 'Hasło i kod są wymagane' });
  }
  
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      select: { 
        id: true, 
        passwordHash: true, 
        twoFactorEnabled: true as any, 
        twoFactorSecret: true as any 
      }
    }) as any;
    
    if (!user || !user.passwordHash) {
      return res.status(400).json({ error: 'Nieprawidłowe żądanie' });
    }
    
    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: 'Weryfikacja dwuetapowa nie jest włączona' });
    }
    
    const isPasswordValid = await comparePassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Nieprawidłowe hasło' });
    }
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret!,
      encoding: 'base32',
      token: code,
      window: 2
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Nieprawidłowy kod weryfikacji' });
    }
    
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: null,
        twoFactorEnabled: false
      } as any
    });
    
    res.json({ message: 'Weryfikacja dwuetapowa została wyłączona' });
  } catch (error) {
    console.error('Error disabling 2FA:', error);
    res.status(500).json({ error: 'Nie udało się wyłączyć weryfikacji dwuetapowej' });
  }
});

app.get('/api/2fa/status', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      select: { twoFactorEnabled: true as any, passwordHash: true }
    }) as any;
    
    res.json({ 
      enabled: user?.twoFactorEnabled || false,
      available: !!user?.passwordHash
    });
  } catch (error) {
    console.error('Error checking 2FA status:', error);
    res.status(500).json({ error: 'Nie udało się sprawdzić statusu 2FA' });
  }
});

app.delete('/api/account', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { password, twoFactorCode } = req.body;
  
  try {
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      select: { 
        id: true,
        passwordHash: true, 
        twoFactorEnabled: true as any, 
        twoFactorSecret: true as any 
      }
    }) as any;
    
    if (!user) {
      return res.status(404).json({ error: 'Użytkownik nie istnieje' });
    }
    
    if (user.passwordHash) {
      if (!password) {
        return res.status(400).json({ error: 'Hasło jest wymagane' });
      }
      
      const isPasswordValid = await comparePassword(password, user.passwordHash);
      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Nieprawidłowe hasło' });
      }
    }
    
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      if (!twoFactorCode) {
        return res.status(400).json({ error: 'Kod 2FA jest wymagany' });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 2
      });
      
      if (!verified) {
        return res.status(401).json({ error: 'Nieprawidłowy kod 2FA' });
      }
    }
    
    await prisma.user.delete({
      where: { id: userId }
    });
    
    res.json({ message: 'Konto zostało usunięte' });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Nie udało się usunąć konta' });
  }
});

const requireAdmin = (req: any, res: any, next: any) => {
  const userId = req.user.id;
  prisma.user.findUnique({ where: { id: userId } }).then(user => {
    if (!user || (!user.isAdmin)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    req.adminUser = user;
    next();
  });
};

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        nickname: true,
        createdAt: true,
        isBanned: true,
        isAdmin: true,
      },
    });
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: 'Could not retrieve users' });
  }
});

app.post('/api/admin/ban', authenticateToken, requireAdmin, async (req, res) => {
  const { userId } = req.body;
  const adminId = (req as any).user.id;

  try {
    if (userId === adminId) {
      return res.status(400).json({ error: 'Nie możesz zbanować samego siebie' });
    }

    const targetUser = await prisma.user.findUnique({ where: { id: userId } });
    if (targetUser?.isAdmin) {
      return res.status(403).json({ error: 'Nie możesz zbanować innego moderatora' });
    }

    await prisma.user.update({
      where: { id: userId },
      data: { isBanned: true },
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Could not ban user' });
  }
});

app.post('/api/admin/unban', authenticateToken, requireAdmin, async (req, res) => {
  const { userId } = req.body;

  try {
    await prisma.user.update({
      where: { id: userId },
      data: { isBanned: false },
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Could not unban user' });
  }
});

app.post('/api/admin/ban-ip', authenticateToken, requireAdmin, async (req, res) => {
  const { userId, reason } = req.body;
  const adminId = (req as any).user.id;

  try {
    if (userId === adminId) {
      return res.status(400).json({ error: 'Nie możesz zbanować samego siebie' });
    }

    const targetUser = await prisma.user.findUnique({ where: { id: userId } });
    if (!targetUser) {
      return res.status(404).json({ error: 'Użytkownik nie znaleziony' });
    }
    
    if (targetUser.isAdmin) {
      return res.status(403).json({ error: 'Nie możesz zbanować innego moderatora' });
    }

    if (!targetUser.lastIpAddress) {
      return res.status(400).json({ error: 'Brak zarejestrowanego adresu IP dla tego użytkownika' });
    }

    await prisma.user.update({
      where: { id: userId },
      data: { isBanned: true },
    });

    await prisma.bannedIP.create({
      data: {
        ipAddress: targetUser.lastIpAddress,
        bannedById: adminId,
        reason: reason || 'Brak podanego powodu',
      },
    });

    res.json({ success: true, bannedIP: '[Ukryty - zhaszowany]' });
  } catch (e: any) {
    if (e.code === 'P2002') {
      return res.status(400).json({ error: 'Ten adres IP jest już zbanowany' });
    }
    console.error('Error banning IP:', e);
    res.status(500).json({ error: 'Nie udało się zbanować adresu IP' });
  }
});

app.post('/api/admin/unban-ip', authenticateToken, requireAdmin, async (req, res) => {
  const { banId } = req.body;

  try {
    await prisma.bannedIP.delete({
      where: { id: banId },
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Nie udało się odbanować adresu IP' });
  }
});

app.get('/api/admin/banned-ips', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const bannedIPs = await prisma.bannedIP.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(bannedIPs);
  } catch (e) {
    res.status(500).json({ error: 'Nie udało się pobrać listy zbanowanych IP' });
  }
});

app.get('/api/admin/mood-entries', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const entries = await prisma.moodEntry.findMany({
      include: {
        user: {
          select: {
            nickname: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });
    res.json(entries);
  } catch (e) {
    res.status(500).json({ error: 'Could not retrieve mood entries' });
  }
});

app.delete('/api/admin/mood-entry/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await prisma.moodEntry.delete({
      where: { id },
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Could not delete mood entry' });
  }
});

const EMPATHETIC_SYSTEM_PROMPT = `You are an empathetic and compassionate AI moderator for a mental health support platform. Your role is to:

1. Listen actively and validate the user's feelings without judgment
2. Show genuine empathy and understanding
3. Respond with warmth, kindness, and emotional intelligence
4. Ask thoughtful follow-up questions to help users explore their emotions
5. Provide supportive and encouraging responses
6. Create a safe, non-judgmental space for users to share their life experiences
7. Use conversational, friendly language (avoid being overly formal or clinical)
8. Never give medical advice or diagnose conditions
9. If someone is in crisis, gently encourage them to seek professional help

Remember: You're a supportive friend and listener, not a therapist. Focus on emotional support, validation, and creating a caring environment where users feel heard and understood.

Respond in Polish if the user writes in Polish, otherwise respond in English.`;

app.post('/api/ai-chat', authenticateToken, async (req, res) => {
  const { message } = req.body;
  const userId = (req as any).user.id;

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ error: 'Message is required' });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(503).json({ error: 'AI is temporarily unavailable. (Missing API key)' });
  }

  try {
    await prisma.chatMessage.create({
      data: {
        userId,
        role: 'user',
        content: message,
      },
    });

    const history = await prisma.chatMessage.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 10,
    });
    history.reverse();

    const conversationHistory = history.map(msg => ({
      role: msg.role === 'user' ? 'user' : 'model',
      parts: [{ text: msg.content }],
    }));

    const chat = model.startChat({
      history: conversationHistory.slice(0, -1),
      generationConfig: {
        temperature: 0.9,
        topK: 1,
        topP: 1,
        maxOutputTokens: 2048,
      },
    });

    let messageToSend = message;
    if (conversationHistory.length <= 1) {
      messageToSend = `${EMPATHETIC_SYSTEM_PROMPT}\n\nUser: ${message}`;
    }

      const candidates = Array.from(new Set([
        GEMINI_MODEL_ID,
        'gemini-2.0-flash',
        'gemini-2.0-flash-lite',
        'gemini-2.5-flash',
      ]));

      let aiResponse = '';
      const attempts: Array<{ model: string; status?: number; message?: string }> = [];
      for (const modelName of candidates) {
        try {
          const m = genAI.getGenerativeModel({
            model: modelName,
            generationConfig: { temperature: 0.9, topK: 1, topP: 1, maxOutputTokens: 2048 },
          });
          const mChat = m.startChat({ history: conversationHistory.slice(0, -1) });
          const r = await mChat.sendMessage(messageToSend);
          aiResponse = r.response.text();
          attempts.push({ model: modelName });
          break;
        } catch (e: any) {
          const status = e?.status || e?.response?.status;
          const message = e?.message;
          console.error('[AI] Model failed:', { modelName, status, message });
          attempts.push({ model: modelName, status, message });
          continue;
        }
      }

      if (!aiResponse) {
        const hasAPIKeyError = attempts.some(a => 
          a.status === 401 || 
          a.status === 403 || 
          a.message?.toLowerCase().includes('api') ||
          a.message?.toLowerCase().includes('key') ||
          a.message?.toLowerCase().includes('invalid')
        );
        
        if (hasAPIKeyError) {
          return res.status(401).json({ 
            error: 'Invalid or expired API key. Please configure a valid Google Gemini API key.' 
          });
        }
        
        const payload: any = { error: 'AI could not generate a response. Please try again.' };
        if (process.env.NODE_ENV !== 'production') {
          payload.debug = { attempts };
        }
        return res.status(502).json(payload);
      }

    const savedResponse = await prisma.chatMessage.create({
      data: {
        userId,
        role: 'assistant',
        content: aiResponse,
      },
    });

    res.json({
      message: aiResponse,
      timestamp: savedResponse.createdAt,
    });
  } catch (error: any) {
    console.error('AI Chat error:', {
      message: error?.message,
      status: error?.status || error?.response?.status,
      details: (error as any)?.errorDetails,
    });
    
    const status = error?.status || error?.response?.status;
    const message = error?.message || '';
    const isAPIKeyError = status === 401 || 
                          status === 403 || 
                          message.toLowerCase().includes('api') ||
                          message.toLowerCase().includes('key') ||
                          message.toLowerCase().includes('invalid') ||
                          message.toLowerCase().includes('quota');
    
    if (isAPIKeyError) {
      return res.status(401).json({ 
        error: 'Invalid or expired API key. Please configure a valid Google Gemini API key.' 
      });
    }
    
    const payload: any = { error: 'Failed to get AI response' };
    if (process.env.NODE_ENV !== 'production') {
      payload.debug = {
        message: error?.message,
        status: error?.status || error?.response?.status,
        details: (error as any)?.errorDetails,
      };
    }
    res.status(500).json(payload);
  }
});

app.get('/api/ai-chat/history', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;

  try {
    const messages = await prisma.chatMessage.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
      take: 50,
    });

    res.json(messages);
  } catch (error) {
    console.error('Error fetching chat history:', error);
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

app.delete('/api/ai-chat/history', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;

  try {
    await prisma.chatMessage.deleteMany({
      where: { userId },
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error clearing chat history:', error);
    res.status(500).json({ error: 'Failed to clear chat history' });
  }
});


app.post('/api/friends/send-request', authenticateToken, async (req, res) => {
  const senderId = (req as any).user.id;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    const receiver = await prisma.user.findFirst({ where: { nickname: username } });
    
    if (!receiver) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (receiver.id === senderId) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }

    const existingFriendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { user1Id: senderId, user2Id: receiver.id },
          { user1Id: receiver.id, user2Id: senderId },
        ],
      },
    });

    if (existingFriendship) {
      return res.status(400).json({ error: 'Already friends' });
    }

    await prisma.friendRequest.deleteMany({
      where: {
        OR: [
          { senderId, receiverId: receiver.id },
          { senderId: receiver.id, receiverId: senderId },
        ],
        status: { not: 'pending' },
      },
    });

    const existingRequest = await prisma.friendRequest.findFirst({
      where: {
        OR: [
          { senderId, receiverId: receiver.id },
          { senderId: receiver.id, receiverId: senderId },
        ],
        status: 'pending',
      },
    });

    if (existingRequest) {
      return res.status(400).json({ error: 'Friend request already sent' });
    }

    const request = await prisma.friendRequest.create({
      data: {
        senderId,
        receiverId: receiver.id,
        status: 'pending',
      },
      include: {
        sender: { select: { id: true, nickname: true } },
        receiver: { select: { id: true, nickname: true } },
      },
    });

    const receiverSocket = Array.from((io as any).sockets.sockets.values())
      .find((s: any) => s.userId === receiver.id) as any;
    
    if (receiverSocket) {
      io.to(receiverSocket.id).emit('friendRequestReceived', {
        id: request.id,
        sender: request.sender,
        createdAt: request.createdAt,
      });
    }

    res.json({ success: true, request });
  } catch (error) {
    console.error('Error sending friend request:', error);
    res.status(500).json({ error: 'Failed to send friend request' });
  }
});

app.get('/api/friends/requests', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;

  try {
    const requests = await prisma.friendRequest.findMany({
      where: { 
        receiverId: userId,
        status: 'pending',
      },
      include: {
        sender: { select: { id: true, nickname: true, createdAt: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    res.json(requests);
  } catch (error) {
    console.error('Error fetching friend requests:', error);
    res.status(500).json({ error: 'Failed to fetch friend requests' });
  }
});

app.post('/api/friends/accept', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { requestId } = req.body;

  try {
    const request = await prisma.friendRequest.findUnique({
      where: { id: requestId },
    });

    if (!request || request.receiverId !== userId) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'Request already processed' });
    }

    // Create friendship and update request status
    await prisma.$transaction([
      prisma.friendship.create({
        data: {
          user1Id: request.senderId,
          user2Id: request.receiverId,
        },
      }),
      prisma.friendRequest.update({
        where: { id: requestId },
        data: { status: 'accepted' },
      }),
    ]);

    // Emit socket event to sender
    const senderSocket = Array.from((io as any).sockets.sockets.values())
      .find((s: any) => s.userId === request.senderId) as any;
    
    if (senderSocket) {
      const accepter = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, nickname: true },
      });
      io.to(senderSocket.id).emit('friendRequestAccepted', {
        friend: accepter,
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error accepting friend request:', error);
    res.status(500).json({ error: 'Failed to accept friend request' });
  }
});

// Reject friend request
app.post('/api/friends/reject', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { requestId } = req.body;

  try {
    const request = await prisma.friendRequest.findUnique({
      where: { id: requestId },
    });

    if (!request || request.receiverId !== userId) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    await prisma.friendRequest.update({
      where: { id: requestId },
      data: { status: 'rejected' },
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error rejecting friend request:', error);
    res.status(500).json({ error: 'Failed to reject friend request' });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;

  try {
    const friendships = await prisma.friendship.findMany({
      where: {
        OR: [
          { user1Id: userId },
          { user2Id: userId },
        ],
      },
      include: {
        user1: { select: { id: true, nickname: true, createdAt: true, lastSeen: true } },
        user2: { select: { id: true, nickname: true, createdAt: true, lastSeen: true } },
      },
    });

    // Extract friend info
    const friends = friendships.map(f => {
      const friend = f.user1Id === userId ? f.user2 : f.user1;
      return {
        id: friend.id,
        nickname: friend.nickname,
        createdAt: friend.createdAt,
        lastSeen: friend.lastSeen,
        friendsSince: f.createdAt,
      };
    });

    res.json(friends);
  } catch (error) {
    console.error('Error fetching friends:', error);
    res.status(500).json({ error: 'Failed to fetch friends' });
  }
});

// Get friend stats (streak, average mood)
app.get('/api/friends/:friendId/stats', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { friendId } = req.params;

  try {
    // Verify friendship
    const friendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { user1Id: userId, user2Id: friendId },
          { user1Id: friendId, user2Id: userId },
        ],
      },
    });

    if (!friendship) {
      return res.status(403).json({ error: 'Not friends with this user' });
    }

    // Get mood entries
    const moodEntries = await prisma.moodEntry.findMany({
      where: { userId: friendId },
      orderBy: { createdAt: 'desc' },
    });

    // Calculate average mood
    const avgMood = moodEntries.length > 0
      ? moodEntries.reduce((sum, e) => sum + e.mood, 0) / moodEntries.length
      : 0;

    // Calculate current streak
    let streak = 0;
    if (moodEntries.length > 0) {
      const sortedEntries = moodEntries.sort((a, b) => 
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      const lastEntry = new Date(sortedEntries[0].createdAt);
      lastEntry.setHours(0, 0, 0, 0);
      
      const daysDiff = Math.floor((today.getTime() - lastEntry.getTime()) / (1000 * 60 * 60 * 24));
      
      if (daysDiff <= 1) {
        streak = 1;
        let currentDate = new Date(lastEntry);
        
        for (let i = 1; i < sortedEntries.length; i++) {
          const entryDate = new Date(sortedEntries[i].createdAt);
          entryDate.setHours(0, 0, 0, 0);
          
          const expectedDate = new Date(currentDate);
          expectedDate.setDate(expectedDate.getDate() - 1);
          
          if (entryDate.getTime() === expectedDate.getTime()) {
            streak++;
            currentDate = entryDate;
          } else if (entryDate.getTime() < expectedDate.getTime()) {
            break;
          }
        }
      }
    }

    res.json({
      totalEntries: moodEntries.length,
      averageMood: parseFloat(avgMood.toFixed(2)),
      currentStreak: streak,
    });
  } catch (error) {
    console.error('Error fetching friend stats:', error);
    res.status(500).json({ error: 'Failed to fetch friend stats' });
  }
});

// Remove friend
app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { friendId } = req.params;

  try {
    const friendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { user1Id: userId, user2Id: friendId },
          { user1Id: friendId, user2Id: userId },
        ],
      },
    });

    if (!friendship) {
      return res.status(404).json({ error: 'Friendship not found' });
    }

    // Get user info before deleting
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { nickname: true },
    });

    // Delete friendship and clean up old friend requests
    await prisma.$transaction([
      prisma.friendship.delete({
        where: { id: friendship.id },
      }),
      prisma.friendRequest.deleteMany({
        where: {
          OR: [
            { senderId: userId, receiverId: friendId },
            { senderId: friendId, receiverId: userId },
          ],
        },
      }),
    ]);

    // Emit socket event to the removed friend
    const friendSocket = Array.from((io as any).sockets.sockets.values())
      .find((s: any) => s.userId === friendId) as any;
    
    if (friendSocket) {
      io.to(friendSocket.id).emit('friendRemoved', {
        friendId: userId,
        nickname: user?.nickname || 'Użytkownik',
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing friend:', error);
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});

// Send direct message to friend
app.post('/api/friends/:friendId/messages', authenticateToken, async (req, res) => {
  const senderId = (req as any).user.id;
  const { friendId } = req.params;
  const { content } = req.body;

  if (!content || content.trim() === '') {
    return res.status(400).json({ error: 'Message content is required' });
  }

  try {
    // Verify friendship
    const friendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { user1Id: senderId, user2Id: friendId },
          { user1Id: friendId, user2Id: senderId },
        ],
      },
    });

    if (!friendship) {
      return res.status(403).json({ error: 'Not friends with this user' });
    }

    // Create message
    const message = await prisma.directMessage.create({
      data: {
        senderId,
        receiverId: friendId,
        content: content.trim(),
      },
      include: {
        sender: { select: { id: true, nickname: true } },
      },
    });

    // Emit socket event to receiver
    const receiverSocket = Array.from((io as any).sockets.sockets.values())
      .find((s: any) => s.userId === friendId) as any;
    
    if (receiverSocket) {
      io.to(receiverSocket.id).emit('directMessage', {
        id: message.id,
        sender: message.sender,
        content: message.content,
        createdAt: message.createdAt,
      });
    }

    res.json({ success: true, message });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get messages with a friend
app.get('/api/friends/:friendId/messages', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;
  const { friendId } = req.params;

  try {
    // Verify friendship
    const friendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { user1Id: userId, user2Id: friendId },
          { user1Id: friendId, user2Id: userId },
        ],
      },
    });

    if (!friendship) {
      return res.status(403).json({ error: 'Not friends with this user' });
    }

    // Get messages
    const messages = await prisma.directMessage.findMany({
      where: {
        OR: [
          { senderId: userId, receiverId: friendId },
          { senderId: friendId, receiverId: userId },
        ],
      },
      include: {
        sender: { select: { id: true, nickname: true } },
        receiver: { select: { id: true, nickname: true } },
      },
      orderBy: { createdAt: 'asc' },
      take: 100,
    });

    // Mark received messages as read
    await prisma.directMessage.updateMany({
      where: {
        senderId: friendId,
        receiverId: userId,
        read: false,
      },
      data: { read: true },
    });

    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get unread message count
app.get('/api/friends/messages/unread', authenticateToken, async (req, res) => {
  const userId = (req as any).user.id;

  try {
    const unreadCount = await prisma.directMessage.count({
      where: {
        receiverId: userId,
        read: false,
      },
    });

    res.json({ count: unreadCount });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    res.status(500).json({ error: 'Failed to fetch unread count' });
  }
});

// --- Socket.IO ---
const helpRequests = new Map<string, string>();

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  try {
    const decoded: any = jwt.verify(token, JWT_SECRET) as any;
    if (!decoded || !decoded.id) return next(new Error('Authentication error'));

    // Fetch user and reject if banned
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user) return next(new Error('Authentication error'));
    if (user.isBanned) return next(new Error('BANNED'));

    (socket as any).userId = user.id;
    next();
  } catch (err) {
    return next(new Error('Authentication error'));
  }
});

io.on('connection', async (socket) => {
  console.log('Socket.IO: user connected:', socket.id, 'handshake auth:', socket.handshake.auth);
  
  // If admin, send current help requests
  const userId = (socket as any).userId;
  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (user?.isAdmin) {
      const requests: Array<{ userId: string; socketId: string; nickname: string }> = [];
      for (const [uid, sid] of helpRequests.entries()) {
        const reqUser = await prisma.user.findUnique({ where: { id: uid }, select: { nickname: true } });
        requests.push({
          userId: uid,
          socketId: sid,
          nickname: reqUser?.nickname || 'Anonim'
        });
      }
      socket.emit('helpRequests', requests);
    }
  } catch (err) {
    console.error('Error checking admin status:', err);
  }

  socket.on('requestHelp', async () => {
    const userId = (socket as any).userId;
    console.log('=== REQUEST HELP ===');
    console.log('requestHelp from userId=', userId, 'socketId=', socket.id);
    helpRequests.set(userId, socket.id);
    
    // Send confirmation to requester
    socket.emit('helpRequestReceived');
    
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { nickname: true },
      });
      console.log('User who requested help:', user);
      
      // Build requests list with correct nicknames for each user
      const requests: { userId: string; socketId: string; nickname: string }[] = [];
      for (const [uid, sid] of helpRequests.entries()) {
        const reqUser = await prisma.user.findUnique({ 
          where: { id: uid }, 
          select: { nickname: true } 
        });
        requests.push({
          userId: uid,
          socketId: sid,
          nickname: reqUser?.nickname || 'Anonim'
        });
      }
      
      console.log('Built requests list:', requests);
      
      // Get all admin users and emit to them
      const admins = await prisma.user.findMany({ where: { isAdmin: true } });
      console.log('Found admins:', admins.map(a => ({ id: a.id, nickname: a.nickname })));
      
      let emittedCount = 0;
      for (const admin of admins) {
        // Find sockets for this admin
        io.sockets.sockets.forEach((sock) => {
          if ((sock as any).userId === admin.id) {
            console.log('Emitting helpRequests to admin socket:', sock.id);
            sock.emit('helpRequests', requests);
            emittedCount++;
          }
        });
      }
      
      console.log('Emitted helpRequests to', emittedCount, 'admin sockets');
      console.log('=== END REQUEST HELP ===');
    } catch (err) {
      console.error('Error handling help request:', err);
    }
  });

  socket.on('adminConnect', (data) => {
    const { userId } = data;
    console.log('adminConnect request from', socket.id, 'to userId', userId);
    const userSocketId = helpRequests.get(userId);
    if (!userSocketId) {
      console.warn('adminConnect: no pending help request for userId', userId);
      return;
    }
    const userSocket = io.sockets.sockets.get(userSocketId);
    if (userSocket) {
      const roomName = `chat-${socket.id}`; // use admin socket id to name room
      userSocket.join(roomName);
      socket.join(roomName);

      prisma.user.findUnique({ where: { id: userId }, select: { nickname: true } })
        .then(async user => {
          const userNickname = user?.nickname || 'Anonim';
          // notify user: admin connected (adminId = socket.id)
          userSocket.emit('adminConnected', { adminId: socket.id, nickname: 'Moderator' });
          // notify admin: include userSocketId and nickname so admin knows who he connected to
          socket.emit('adminConnectedToUser', { userId, userSocketId, userNickname });
          helpRequests.delete(userId);
          console.log('adminConnect: connected admin', socket.id, 'and userSocket', userSocketId, 'room', roomName);
          
          // Broadcast updated help requests list to all admins
          const requests = Array.from(helpRequests.entries()).map(([uid, sid]) => ({
            userId: uid,
            socketId: sid,
            nickname: 'Anonim'
          }));
          
          const admins = await prisma.user.findMany({ where: { isAdmin: true } });
          for (const admin of admins) {
            io.sockets.sockets.forEach((sock) => {
              if ((sock as any).userId === admin.id) {
                sock.emit('helpRequests', requests);
              }
            });
          }
        })
        .catch(async err => {
          console.error('Error fetching user nickname', err);
          userSocket.emit('adminConnected', { adminId: socket.id, nickname: 'Moderator' });
          socket.emit('adminConnectedToUser', { userId, userSocketId, userNickname: 'Anonim' });
          helpRequests.delete(userId);
          
          // Broadcast updated help requests list to all admins
          const requests = Array.from(helpRequests.entries()).map(([uid, sid]) => ({
            userId: uid,
            socketId: sid,
            nickname: 'Anonim'
          }));
          
          try {
            const admins = await prisma.user.findMany({ where: { isAdmin: true } });
            for (const admin of admins) {
              io.sockets.sockets.forEach((sock) => {
                if ((sock as any).userId === admin.id) {
                  sock.emit('helpRequests', requests);
                }
              });
            }
          } catch (e) {
            console.error('Error broadcasting help requests after error', e);
          }
        });
    } else {
      console.warn('adminConnect: user socket not found for socketId', userSocketId);
    }
  });

  // Kiedy ktokolwiek wysyła privateMessage -> emit do room chat-<adminSocketId>
  socket.on('privateMessage', async (data) => {
    try {
      const { to, message } = data; // 'to' can be adminSocketId or userSocketId
      
      // Find which room this socket is in (should be chat-<something>)
      let room = `chat-${to}`;
      const socketRooms = Array.from(socket.rooms);
      const chatRoom = socketRooms.find(r => r.startsWith('chat-'));
      
      if (chatRoom) {
        room = chatRoom; // Use the actual room this socket is in
        console.log('Found chat room:', room);
      } else {
        console.log('No chat room found, using default:', room);
      }

      // pobierz nickname nadawcy
      let senderNickname = 'Użytkownik';
      const senderId = (socket as any).userId;
      try {
        const user = await prisma.user.findUnique({ where: { id: senderId }, select: { nickname: true, isAdmin: true } });
        if (user && user.nickname) {
          senderNickname = user.isAdmin ? 'Moderator' : user.nickname;
        }
      } catch (err) {
        console.warn('Could not fetch nickname for sender', err);
      }

      io.to(room).emit('privateMessage', {
        from: socket.id,
        sender: senderNickname,
        senderNickname: senderNickname,
        message,
        timestamp: new Date().toISOString(),
      });

      console.log('privateMessage emitted to room', room, 'from', senderNickname, ':', message);
    } catch (err) {
      console.error('privateMessage handler error', err);
    }
  });

  socket.on('leaveChat', async (data) => {
    try {
      const userId = (socket as any).userId;
      
      // Find the chat room this socket is in
      const socketRooms = Array.from(socket.rooms);
      const chatRoom = socketRooms.find(r => r.startsWith('chat-'));
      
      if (!chatRoom) {
        console.warn('leaveChat: socket is not in any chat room');
        return;
      }
      
      console.log('leaveChat: found chat room:', chatRoom);
      
      // Get user nickname
      let nickname = 'Rozmówca';
      try {
        const user = await prisma.user.findUnique({ where: { id: userId }, select: { nickname: true, isAdmin: true } });
        if (user && user.nickname) {
          nickname = user.isAdmin ? 'Moderator' : user.nickname;
        }
      } catch (err) {
        console.warn('Could not fetch nickname for leaveChat', err);
      }

      // Notify other person in the room
      socket.to(chatRoom).emit('chatEnded', { nickname });
      console.log('leaveChat: notified room', chatRoom, 'that', nickname, 'left');
      
      // Leave the room
      socket.leave(chatRoom);
    } catch (err) {
      console.error('leaveChat handler error', err);
    }
  });

  socket.on('disconnect', (reason) => {
    const userId = (socket as any).userId;
    const nickname = (socket as any).nickname;
    console.log('Socket disconnected:', socket.id, 'reason:', reason, 'userId:', userId, 'nickname:', nickname);
    
    // Notify other users in private chat rooms
    const rooms = Array.from(socket.rooms);
    console.log('Rooms for disconnected socket:', rooms);
    
    for (const room of rooms) {
      console.log('Checking room:', room, 'type:', typeof room);
      if (room !== socket.id && room.startsWith('chat-')) {
        console.log('Emitting userDisconnected to room:', room, 'from socket:', socket.id);
        // Use io.to() to emit to all sockets in room except sender
        io.to(room).emit('userDisconnected', { 
          socketId: socket.id, 
          userId: userId,
          nickname: nickname || 'Użytkownik'
        });
        console.log('Successfully notified room', room, 'about disconnect');
      }
    }
    
    // usuń z mapy, jeśli istniało
    for (const [k, v] of helpRequests.entries()) {
      if (v === socket.id) helpRequests.delete(k);
    }
  });
});

httpServer.listen(3001, () => {
  console.log('Backend listening on port 3001');
});
