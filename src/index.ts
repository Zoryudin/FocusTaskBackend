import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const envPaths = new Set([
  path.resolve(process.cwd(), '.env'),
  path.resolve(process.cwd(), '..', '.env'),
  path.resolve(__dirname, '..', '.env'),
  path.resolve(__dirname, '..', '..', '.env'),
]);

for (const envPath of envPaths) {
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath, override: false });
  }
}

type PlannerPriority = 'Rendah' | 'Sedang' | 'Tinggi';
type PlannerTask = {
  title: string;
  description?: string;
  priority: PlannerPriority;
  time: string;
  days: string[];
};
type WeekdayKey = 'senin' | 'selasa' | 'rabu' | 'kamis' | 'jumat' | 'sabtu' | 'minggu';
type WeeklyRequiredTaskPayload = {
  title: string;
  day: WeekdayKey;
  startTime: string;
  endTime: string;
  location: string;
  note: string;
  priority: PlannerPriority;
  active: boolean;
};
type ProfilePayload = {
  name: string;
  email: string;
  bio: string | null;
  avatarUrl: string | null;
};
type RegisterPayload = {
  name: string;
  email: string;
  password: string;
  bio: string | null;
};
type LoginPayload = {
  email: string;
  password: string;
};
type AuthenticatedRequest = express.Request & {
  authUserId?: string;
};

const VALID_DAYS = ['senin', 'selasa', 'rabu', 'kamis', 'jumat', 'sabtu', 'minggu'] as const;
const DAY_TO_INDEX: Record<WeekdayKey, number> = {
  minggu: 0,
  senin: 1,
  selasa: 2,
  rabu: 3,
  kamis: 4,
  jumat: 5,
  sabtu: 6,
};
const PRIORITY_MAP: Record<string, PlannerPriority> = {
  rendah: 'Rendah',
  low: 'Rendah',
  sedang: 'Sedang',
  medium: 'Sedang',
  tinggi: 'Tinggi',
  high: 'Tinggi',
};

const GEMINI_MODEL = process.env.GEMINI_MODEL?.trim() || 'gemini-2.5-flash';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL ?? process.env.DIRECT_URL;
const JWT_SECRET =
  process.env.JWT_SECRET?.trim() || 'focus-task-dev-secret-change-this';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN?.trim() || '7d';

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL atau DIRECT_URL belum diatur');
}

const adapter = new PrismaPg({
  connectionString: DATABASE_URL,
});

const app = express();
const prisma = new PrismaClient({
  adapter,
  log: ['query', 'error', 'warn'],
});
const PORT = process.env.PORT || 5000;
const DEFAULT_USER_ID = process.env.DEFAULT_USER_ID?.trim() || 'default-user-id';
const DEFAULT_USER_EMAIL =
  process.env.DEFAULT_USER_EMAIL?.trim() || 'tester@focustask.local';
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME?.trim() || 'FocusTask User';
const DEFAULT_USER_BIO =
  process.env.DEFAULT_USER_BIO?.trim() || 'Productivity enthusiast & FocusTask user.';
const DEFAULT_USER_AVATAR_URL = process.env.DEFAULT_USER_AVATAR_URL?.trim() || null;
const DEFAULT_USER_PASSWORD = process.env.DEFAULT_USER_PASSWORD?.trim() || '12345678';

app.use(cors());
app.use(express.json());

const AUTH_HASH_PREFIX = 'scrypt';

const hashPassword = (password: string): string => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${AUTH_HASH_PREFIX}$${salt}$${hash}`;
};

const verifyPassword = (password: string, passwordHash: string): boolean => {
  if (!passwordHash) return false;

  const [prefix, salt, storedHash] = passwordHash.split('$');
  if (prefix !== AUTH_HASH_PREFIX || !salt || !storedHash) {
    return false;
  }

  const computedHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');
  const computedBuffer = Buffer.from(computedHash, 'hex');

  if (storedBuffer.length !== computedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(storedBuffer, computedBuffer);
};

const createAccessToken = (userId: string, email: string): string =>
  jwt.sign({ sub: userId, email }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN as SignOptions['expiresIn'],
  });

const getAuthUserId = (req: express.Request): string => {
  const userId = (req as AuthenticatedRequest).authUserId;
  if (!userId) {
    throw new Error('Unauthorized request context');
  }

  return userId;
};

const requireAuth: express.RequestHandler = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token tidak ditemukan' });
  }

  const token = authorization.slice('Bearer '.length).trim();
  if (!token) {
    return res.status(401).json({ error: 'Token tidak valid' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    const subject = typeof decoded.sub === 'string' ? decoded.sub : '';
    if (!subject) {
      return res.status(401).json({ error: 'Token tidak valid' });
    }

    (req as AuthenticatedRequest).authUserId = subject;
    return next();
  } catch {
    return res.status(401).json({ error: 'Token tidak valid atau kadaluarsa' });
  }
};

const normalizePriority = (value: unknown): PlannerPriority => {
  if (typeof value !== 'string') return 'Sedang';
  return PRIORITY_MAP[value.trim().toLowerCase()] ?? 'Sedang';
};

const normalizeTime = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;

  const match = value.trim().match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
  if (!match) return null;

  const hours = match[1].padStart(2, '0');
  const minutes = match[2];
  return `${hours}:${minutes}`;
};

const normalizeDays = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];

  const normalized = value
    .map((day) => (typeof day === 'string' ? day.trim().toLowerCase() : ''))
    .filter((day): day is (typeof VALID_DAYS)[number] =>
      VALID_DAYS.includes(day as (typeof VALID_DAYS)[number])
    );

  return Array.from(new Set(normalized));
};

const parseJsonPayload = (text: string): unknown => {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error('AI response is empty');
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (!fencedMatch?.[1]) {
      throw new Error('AI response is not valid JSON');
    }
    return JSON.parse(fencedMatch[1]);
  }
};

const sanitizePlannerTasks = (payload: unknown): PlannerTask[] => {
  const rawTasks = Array.isArray(payload)
    ? payload
    : typeof payload === 'object' &&
        payload !== null &&
        Array.isArray((payload as { tasks?: unknown }).tasks)
      ? (payload as { tasks: unknown[] }).tasks
      : [];

  const sanitized: PlannerTask[] = [];

  for (const task of rawTasks) {
    if (!task || typeof task !== 'object') continue;

    const typedTask = task as Record<string, unknown>;
    const title = typeof typedTask.title === 'string' ? typedTask.title.trim() : '';
    if (!title) continue;

    const time = normalizeTime(typedTask.time);
    const days = normalizeDays(typedTask.days);
    if (!time || days.length === 0) continue;

    const description =
      typeof typedTask.description === 'string' ? typedTask.description.trim() : undefined;

    sanitized.push({
      title,
      description,
      priority: normalizePriority(typedTask.priority),
      time,
      days,
    });
  }

  return sanitized;
};

const generatePlannerTasks = async (prompt: string): Promise<PlannerTask[]> => {
  if (!GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY belum diatur di file .env');
  }

  const systemInstruction = [
    'Kamu adalah asisten penjadwalan untuk aplikasi to-do berbahasa Indonesia.',
    'Balas HANYA dalam JSON valid tanpa teks tambahan.',
    'Format output:',
    '{ "tasks": [{ "title": string, "description": string, "priority": "Rendah" | "Sedang" | "Tinggi", "time": "HH:MM", "days": ["senin" | "selasa" | "rabu" | "kamis" | "jumat" | "sabtu" | "minggu"] }] }',
    'Buat 3-10 task yang realistis berdasarkan prompt pengguna.',
    'Semua jam gunakan format 24 jam HH:MM.',
  ].join('\n');

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: {
          parts: [{ text: systemInstruction }],
        },
        contents: [
          {
            role: 'user',
            parts: [{ text: prompt }],
          },
        ],
        generationConfig: {
          temperature: 0.4,
          responseMimeType: 'application/json',
        },
      }),
    }
  );

  const result = (await response.json()) as {
    candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    error?: { message?: string };
  };

  if (!response.ok) {
    throw new Error(result.error?.message || 'Gagal memanggil Gemini API');
  }

  const aiText = result.candidates?.[0]?.content?.parts?.map((part) => part.text ?? '').join('\n');
  if (!aiText) {
    throw new Error('Gemini tidak mengembalikan konten');
  }

  const parsed = parseJsonPayload(aiText);
  const tasks = sanitizePlannerTasks(parsed);

  if (tasks.length === 0) {
    throw new Error('Output Gemini tidak valid untuk format jadwal');
  }

  return tasks;
};

type TaskCreatePayload = {
  title: string;
  description: string | null;
  priority: PlannerPriority;
  time: Date;
  date: Date;
  completed: boolean;
  consequence: string | null;
};

const TASK_CONSEQUENCE_MAP: Record<PlannerPriority, string> = {
  Rendah:
    'Progres melambat dan ritme fokus harian terganggu jika tugas ini dilewatkan.',
  Sedang:
    'Jika tugas ini tidak selesai, beban kerja akan menumpuk dan target berikutnya ikut tertunda.',
  Tinggi:
    'Jika tugas ini gagal dikerjakan, target utama hari ini berisiko gagal dan tekanan kerja meningkat.',
};

class ValidationError extends Error {}

const parseDateInput = (value: unknown, fieldName: string): Date => {
  if (!(typeof value === 'string' || value instanceof Date)) {
    throw new ValidationError(`${fieldName} wajib berupa tanggal yang valid`);
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new ValidationError(`${fieldName} tidak valid`);
  }

  return parsed;
};

const parseTaskPayload = (value: unknown): TaskCreatePayload => {
  if (!value || typeof value !== 'object') {
    throw new ValidationError('Payload task tidak valid');
  }

  const body = value as Record<string, unknown>;
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  if (!title) {
    throw new ValidationError('Judul task wajib diisi');
  }

  const description =
    typeof body.description === 'string' && body.description.trim()
      ? body.description.trim()
      : null;
  const priority = normalizePriority(body.priority);
  const time = parseDateInput(body.time, 'time');
  const date = parseDateInput(body.date, 'date');
  const completed = Boolean(body.completed);
  const consequenceValue =
    typeof body.consequence === 'string' && body.consequence.trim()
      ? body.consequence.trim()
      : `${title}: ${TASK_CONSEQUENCE_MAP[priority]}`;

  return {
    title,
    description,
    priority,
    time,
    date,
    completed,
    consequence: consequenceValue,
  };
};

const startOfDay = (value: Date): Date => {
  const date = new Date(value);
  date.setHours(0, 0, 0, 0);
  return date;
};

const normalizeWeeklyDay = (value: unknown): WeekdayKey => {
  if (typeof value !== 'string') {
    throw new ValidationError('Hari tugas wajib tidak valid');
  }

  const normalized = value.trim().toLowerCase() as WeekdayKey;
  if (!VALID_DAYS.includes(normalized)) {
    throw new ValidationError('Hari tugas wajib harus salah satu dari senin sampai minggu');
  }

  return normalized;
};

const buildConsequence = (title: string, priority: PlannerPriority): string =>
  `${title}: ${TASK_CONSEQUENCE_MAP[priority]}`;

const combineDateAndTime = (baseDate: Date, timeValue: string): Date => {
  const [hours, minutes] = timeValue.split(':').map((value) => Number.parseInt(value, 10));
  const parsedDate = new Date(baseDate);
  parsedDate.setHours(hours, minutes, 0, 0);
  return parsedDate;
};

const parseWeeklyRequiredTaskPayload = (value: unknown): WeeklyRequiredTaskPayload => {
  if (!value || typeof value !== 'object') {
    throw new ValidationError('Payload weekly required task tidak valid');
  }

  const body = value as Record<string, unknown>;

  const title = typeof body.title === 'string' ? body.title.trim() : '';
  if (!title) {
    throw new ValidationError('Judul weekly required task wajib diisi');
  }

  const day = normalizeWeeklyDay(body.day);
  const startTime = normalizeTime(body.startTime);
  const endTime = normalizeTime(body.endTime);
  if (!startTime || !endTime) {
    throw new ValidationError('Jam mulai dan selesai wajib dalam format HH:mm');
  }

  const location = typeof body.location === 'string' ? body.location.trim() : '';
  if (!location) {
    throw new ValidationError('Lokasi weekly required task wajib diisi');
  }

  const note = typeof body.note === 'string' ? body.note.trim() : '';
  if (!note) {
    throw new ValidationError('Catatan weekly required task wajib diisi');
  }

  return {
    title,
    day,
    startTime,
    endTime,
    location,
    note,
    priority: normalizePriority(body.priority ?? 'Tinggi'),
    active: body.active === undefined ? true : Boolean(body.active),
  };
};

const parseProfilePayload = (value: unknown): ProfilePayload => {
  if (!value || typeof value !== 'object') {
    throw new ValidationError('Payload profile tidak valid');
  }

  const body = value as Record<string, unknown>;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name) {
    throw new ValidationError('Nama wajib diisi');
  }

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!email) {
    throw new ValidationError('Email wajib diisi');
  }

  if (!emailRegex.test(email)) {
    throw new ValidationError('Format email tidak valid');
  }

  const bio =
    typeof body.bio === 'string' && body.bio.trim().length > 0
      ? body.bio.trim()
      : null;
  const rawAvatarUrl = typeof body.avatarUrl === 'string' ? body.avatarUrl.trim() : '';

  let avatarUrl: string | null = null;
  if (rawAvatarUrl.length > 0) {
    const isDataUrl = /^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(rawAvatarUrl);
    const isHttpUrl = /^https?:\/\/.+/i.test(rawAvatarUrl);
    if (!isDataUrl && !isHttpUrl) {
      throw new ValidationError('Format avatar URL tidak valid');
    }
    avatarUrl = rawAvatarUrl;
  }

  return {
    name,
    email,
    bio,
    avatarUrl,
  };
};

const parseRegisterPayload = (value: unknown): RegisterPayload => {
  if (!value || typeof value !== 'object') {
    throw new ValidationError('Payload register tidak valid');
  }

  const body = value as Record<string, unknown>;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name) {
    throw new ValidationError('Nama wajib diisi');
  }

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!email || !emailRegex.test(email)) {
    throw new ValidationError('Email tidak valid');
  }

  const password = typeof body.password === 'string' ? body.password : '';
  if (password.length < 6) {
    throw new ValidationError('Password minimal 6 karakter');
  }

  const bio =
    typeof body.bio === 'string' && body.bio.trim().length > 0 ? body.bio.trim() : null;

  return {
    name,
    email,
    password,
    bio,
  };
};

const parseLoginPayload = (value: unknown): LoginPayload => {
  if (!value || typeof value !== 'object') {
    throw new ValidationError('Payload login tidak valid');
  }

  const body = value as Record<string, unknown>;
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!email || !emailRegex.test(email)) {
    throw new ValidationError('Email tidak valid');
  }

  if (!password) {
    throw new ValidationError('Password wajib diisi');
  }

  return {
    email,
    password,
  };
};

const toProfileResponse = (user: {
  id: string;
  name: string | null;
  email: string;
  bio: string | null;
  avatarUrl: string | null;
}) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  bio: user.bio,
  avatarUrl: user.avatarUrl,
});

const syncWeeklyRequiredTaskInstances = async (userId: string): Promise<void> => {
  const templates = await prisma.weeklyRequiredTask.findMany({
    where: { userId, active: true },
  });

  if (!templates.length) return;

  const now = new Date();
  const rangeStart = startOfDay(new Date(now.getTime() - 24 * 60 * 60 * 1000));
  const rangeEnd = startOfDay(new Date(now.getTime() + 8 * 24 * 60 * 60 * 1000));

  const targetDates: Date[] = [];
  for (
    let cursor = new Date(rangeStart);
    cursor.getTime() <= rangeEnd.getTime();
    cursor.setDate(cursor.getDate() + 1)
  ) {
    targetDates.push(startOfDay(new Date(cursor)));
  }

  for (const targetDate of targetDates) {
    const targetDayIndex = targetDate.getDay();
    const matchedTemplates = templates.filter(
      (template) => DAY_TO_INDEX[template.day as WeekdayKey] === targetDayIndex
    );

    for (const template of matchedTemplates) {
      const taskTime = combineDateAndTime(targetDate, template.startTime);
      const normalizedPriority = normalizePriority(template.priority);
      const existingTask = await prisma.task.findFirst({
        where: {
          userId,
          weeklyRequiredTaskId: template.id,
          date: targetDate,
        },
      });

      if (existingTask) {
        await prisma.task.update({
          where: { id: existingTask.id },
          data: {
            title: template.title,
            description: template.note,
            priority: normalizedPriority,
            time: taskTime,
            consequence: buildConsequence(template.title, normalizedPriority),
          },
        });
      } else {
        await prisma.task.create({
          data: {
            title: template.title,
            description: template.note,
            priority: normalizedPriority,
            time: taskTime,
            date: targetDate,
            consequence: buildConsequence(template.title, normalizedPriority),
            userId,
            weeklyRequiredTaskId: template.id,
          },
        });
      }
    }
  }
};

const ensureDefaultUserExists = async (): Promise<void> => {
  await prisma.user.upsert({
    where: { id: DEFAULT_USER_ID },
    update: {
      email: DEFAULT_USER_EMAIL,
      name: DEFAULT_USER_NAME,
      bio: DEFAULT_USER_BIO,
      avatarUrl: DEFAULT_USER_AVATAR_URL,
      passwordHash: hashPassword(DEFAULT_USER_PASSWORD),
    },
    create: {
      id: DEFAULT_USER_ID,
      email: DEFAULT_USER_EMAIL,
      name: DEFAULT_USER_NAME,
      bio: DEFAULT_USER_BIO,
      avatarUrl: DEFAULT_USER_AVATAR_URL,
      passwordHash: hashPassword(DEFAULT_USER_PASSWORD),
    },
  });
};


// Endpoints
app.post('/api/auth/register', async (req, res) => {
  try {
    const payload = parseRegisterPayload(req.body);
    const duplicate = await prisma.user.findUnique({
      where: { email: payload.email },
      select: { id: true },
    });

    if (duplicate) {
      return res.status(409).json({ error: 'Email sudah terdaftar' });
    }

    const createdUser = await prisma.user.create({
      data: {
        name: payload.name,
        email: payload.email,
        bio: payload.bio,
        avatarUrl: null,
        passwordHash: hashPassword(payload.password),
      },
      select: {
        id: true,
        name: true,
        email: true,
        bio: true,
        avatarUrl: true,
      },
    });

    return res.status(201).json({
      accessToken: createAccessToken(createdUser.id, createdUser.email),
      user: toProfileResponse(createdUser),
    });
  } catch (error) {
    console.error('Register error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal melakukan registrasi' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const payload = parseLoginPayload(req.body);
    const user = await prisma.user.findUnique({
      where: { email: payload.email },
      select: {
        id: true,
        name: true,
        email: true,
        bio: true,
        avatarUrl: true,
        passwordHash: true,
      },
    });

    if (!user || !verifyPassword(payload.password, user.passwordHash)) {
      return res.status(401).json({ error: 'Email atau password salah' });
    }

    return res.json({
      accessToken: createAccessToken(user.id, user.email),
      user: toProfileResponse(user),
    });
  } catch (error) {
    console.error('Login error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal melakukan login' });
  }
});

app.post('/api/auth/guest', async (_req, res) => {
  try {
    const randomToken = `${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const guestEmail = `guest-${randomToken}@focustask.local`;

    const guestUser = await prisma.user.create({
      data: {
        name: 'Guest User',
        email: guestEmail,
        bio: 'Akun tamu sementara',
        avatarUrl: null,
        passwordHash: hashPassword(crypto.randomBytes(12).toString('hex')),
      },
      select: {
        id: true,
        name: true,
        email: true,
        bio: true,
        avatarUrl: true,
      },
    });

    return res.status(201).json({
      accessToken: createAccessToken(guestUser.id, guestUser.email),
      user: toProfileResponse(guestUser),
    });
  } catch (error) {
    console.error('Guest login error:', error);
    return res.status(500).json({ error: 'Gagal masuk sebagai tamu' });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        bio: true,
        avatarUrl: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'User tidak ditemukan' });
    }

    return res.json(toProfileResponse(user));
  } catch (error) {
    console.error('Fetch auth user error:', error);
    return res.status(500).json({ error: 'Gagal mengambil data user' });
  }
});

app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        bio: true,
        avatarUrl: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'Profil tidak ditemukan' });
    }

    return res.json(toProfileResponse(user));
  } catch (error) {
    console.error('Fetch profile error:', error);
    return res.status(500).json({ error: 'Gagal mengambil profil' });
  }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const payload = parseProfilePayload(req.body);
    const userId = getAuthUserId(req);

    const duplicateEmailUser = await prisma.user.findFirst({
      where: {
        email: payload.email,
        id: { not: userId },
      },
      select: { id: true },
    });

    if (duplicateEmailUser) {
      return res.status(409).json({ error: 'Email sudah digunakan pengguna lain' });
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        name: payload.name,
        email: payload.email,
        bio: payload.bio,
        avatarUrl: payload.avatarUrl,
      },
      select: {
        id: true,
        name: true,
        email: true,
        bio: true,
        avatarUrl: true,
      },
    });

    return res.json(toProfileResponse(updatedUser));
  } catch (error) {
    console.error('Update profile error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal memperbarui profil' });
  }
});

app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    await syncWeeklyRequiredTaskInstances(userId);

    const tasks = await prisma.task.findMany({
      where: { userId },
      orderBy: [{ date: 'asc' }, { time: 'asc' }],
    });
    res.json(tasks);
  } catch (error) {
    console.error('Fetch tasks error:', error);
    res.status(500).json({ error: 'Gagal mengambil task' });
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const payload = parseTaskPayload(req.body);
    const userId = getAuthUserId(req);

    const task = await prisma.task.create({
      data: {
        ...payload,
        userId,
      },
    });

    res.status(201).json(task);
  } catch (error) {
    console.error('Create task error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal membuat task' });
  }
});

app.post('/api/tasks/bulk', requireAuth, async (req, res) => {
  try {
    const tasksPayload =
      typeof req.body === 'object' && req.body !== null
        ? (req.body as { tasks?: unknown }).tasks
        : undefined;

    if (!Array.isArray(tasksPayload) || tasksPayload.length === 0) {
      throw new ValidationError('tasks wajib berupa array dan tidak boleh kosong');
    }

    const userId = getAuthUserId(req);
    const parsedTasks = tasksPayload.map((taskPayload) => parseTaskPayload(taskPayload));

    const createdTasks = await prisma.$transaction(
      parsedTasks.map((taskPayload) =>
        prisma.task.create({
          data: {
            ...taskPayload,
            userId,
          },
        })
      )
    );

    return res.status(201).json(createdTasks);
  } catch (error) {
    console.error('Create bulk tasks error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal membuat task secara bulk' });
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const taskId = req.params.id?.trim();
    if (!taskId) {
      throw new ValidationError('ID task tidak valid');
    }

    const userId = getAuthUserId(req);
    const result = await prisma.task.deleteMany({
      where: { id: taskId, userId },
    });

    if (result.count === 0) {
      return res.status(404).json({ error: 'Task tidak ditemukan' });
    }

    return res.status(204).send();
  } catch (error) {
    console.error('Delete task error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal menghapus task' });
  }
});

app.get('/api/weekly-required-tasks', requireAuth, async (req, res) => {
  try {
    const userId = getAuthUserId(req);

    const weeklyRequiredTasks = await prisma.weeklyRequiredTask.findMany({
      where: { userId },
    });

    const sorted = weeklyRequiredTasks.sort((a, b) => {
      const aDayIndex = DAY_TO_INDEX[a.day as WeekdayKey] ?? 99;
      const bDayIndex = DAY_TO_INDEX[b.day as WeekdayKey] ?? 99;
      const dayCompare = aDayIndex - bDayIndex;

      if (dayCompare !== 0) return dayCompare;
      return a.startTime.localeCompare(b.startTime);
    });

    return res.json(sorted);
  } catch (error) {
    console.error('Fetch weekly required tasks error:', error);
    return res.status(500).json({ error: 'Gagal mengambil weekly required task' });
  }
});

app.post('/api/weekly-required-tasks', requireAuth, async (req, res) => {
  try {
    const payload = parseWeeklyRequiredTaskPayload(req.body);
    const userId = getAuthUserId(req);

    const createdTask = await prisma.weeklyRequiredTask.create({
      data: {
        ...payload,
        userId,
      },
    });

    await syncWeeklyRequiredTaskInstances(userId);

    return res.status(201).json(createdTask);
  } catch (error) {
    console.error('Create weekly required task error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal membuat weekly required task' });
  }
});

app.put('/api/weekly-required-tasks/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id?.trim();
    if (!id) {
      throw new ValidationError('ID weekly required task tidak valid');
    }

    const payload = parseWeeklyRequiredTaskPayload(req.body);
    const userId = getAuthUserId(req);

    const updated = await prisma.weeklyRequiredTask.updateMany({
      where: { id, userId },
      data: payload,
    });

    if (updated.count === 0) {
      return res.status(404).json({ error: 'Weekly required task tidak ditemukan' });
    }

    await syncWeeklyRequiredTaskInstances(userId);

    const fresh = await prisma.weeklyRequiredTask.findUnique({
      where: { id },
    });

    return res.json(fresh);
  } catch (error) {
    console.error('Update weekly required task error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal mengubah weekly required task' });
  }
});

app.delete('/api/weekly-required-tasks/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id?.trim();
    if (!id) {
      throw new ValidationError('ID weekly required task tidak valid');
    }

    const userId = getAuthUserId(req);

    const deletedTask = await prisma.weeklyRequiredTask.deleteMany({
      where: { id, userId },
    });

    if (deletedTask.count === 0) {
      return res.status(404).json({ error: 'Weekly required task tidak ditemukan' });
    }

    await prisma.task.deleteMany({
      where: { userId, weeklyRequiredTaskId: id },
    });

    return res.status(204).send();
  } catch (error) {
    console.error('Delete weekly required task error:', error);
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(500).json({ error: 'Gagal menghapus weekly required task' });
  }
});

app.post('/api/smart-planner', requireAuth, async (req, res) => {
  const { prompt } = req.body;
  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  try {
    const plannedTasks = await generatePlannerTasks(prompt.trim());

    return res.json({
      success: true,
      data: plannedTasks,
      message: 'Jadwal berhasil dianalisis.',
    });
  } catch (error) {
    console.error('Smart planner error:', error);
    const message = error instanceof Error ? error.message : 'Gagal memproses smart planner';
    return res.status(500).json({ error: message });
  }
});

const startServer = async () => {
  await ensureDefaultUserExists();

  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
};

void startServer().catch((error) => {
  console.error('Gagal memulai server:', error);
  process.exit(1);
});
