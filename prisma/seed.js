require('dotenv/config');
const { PrismaPg } = require('@prisma/adapter-pg');
const { PrismaClient } = require('@prisma/client');
const crypto = require('node:crypto');

const connectionString = process.env.DIRECT_URL || process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error('DIRECT_URL atau DATABASE_URL wajib diisi untuk seed');
}

const adapter = new PrismaPg({
  connectionString,
});

const prisma = new PrismaClient({
  adapter,
});

const TEST_USER_ID = 'default-user-id';
const TEST_USER_EMAIL = 'tester@focustask.local';
const TEST_USER_NAME = 'FocusTask Tester';
const TEST_USER_BIO = 'Productivity enthusiast & FocusTask user.';
const TEST_USER_AVATAR_URL = null;
const TEST_USER_PASSWORD = process.env.DEFAULT_USER_PASSWORD || '12345678';

const hashPassword = (password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derivedKey}`;
};

const consequenceByPriority = {
  Rendah:
    'Progres melambat dan ritme fokus harian terganggu jika tugas ini dilewatkan.',
  Sedang:
    'Jika tugas ini tidak selesai, beban kerja akan menumpuk dan target berikutnya ikut tertunda.',
  Tinggi:
    'Jika tugas ini gagal dikerjakan, target utama hari ini berisiko gagal dan tekanan kerja meningkat.',
};

const buildConsequence = (title, priority) =>
  `${title}: ${consequenceByPriority[priority]}`;

const startOfDay = (date) => {
  const value = new Date(date);
  value.setHours(0, 0, 0, 0);
  return value;
};

const atTime = (baseDate, hour, minute) => {
  const value = new Date(baseDate);
  value.setHours(hour, minute, 0, 0);
  return value;
};

const dayName = (date) => {
  const days = [
    'minggu',
    'senin',
    'selasa',
    'rabu',
    'kamis',
    'jumat',
    'sabtu',
  ];
  return days[new Date(date).getDay()];
};

async function main() {
  const now = new Date();
  const today = startOfDay(now);
  const tomorrow = startOfDay(new Date(now.getTime() + 24 * 60 * 60 * 1000));
  const yesterday = startOfDay(new Date(now.getTime() - 24 * 60 * 60 * 1000));

  const taskDrafts = [
    {
      title: 'Finalisasi presentasi produk',
      description: 'Perbaiki slide utama dan data KPI terbaru.',
      priority: 'Tinggi',
      date: today,
      time: atTime(today, 17, 0),
      completed: false,
    },
    {
      title: 'Follow up calon klien',
      description: 'Kirim ringkasan penawaran dan jadwalkan demo.',
      priority: 'Tinggi',
      date: tomorrow,
      time: atTime(tomorrow, 11, 30),
      completed: false,
    },
    {
      title: 'Review backlog sprint',
      description: 'Prioritaskan ticket untuk rilis minggu ini.',
      priority: 'Sedang',
      date: today,
      time: atTime(today, 14, 0),
      completed: false,
    },
    {
      title: 'Olahraga sore 30 menit',
      description: 'Jaga konsistensi kebugaran.',
      priority: 'Rendah',
      date: today,
      time: atTime(today, 18, 30),
      completed: false,
    },
    {
      title: 'Rapikan catatan meeting',
      description: 'Simpan keputusan meeting ke dokumen tim.',
      priority: 'Sedang',
      date: yesterday,
      time: atTime(yesterday, 16, 0),
      completed: true,
    },
  ];

  const presetBaseDate = today;
  const presetDrafts = [
    {
      title: 'Deep Work Pagi',
      description: 'Sesi fokus tanpa distraksi selama 90 menit.',
      priority: 'Tinggi',
      day: 'senin',
      time: atTime(presetBaseDate, 8, 0),
      active: true,
    },
    {
      title: 'Review Harian',
      description: 'Evaluasi progres dan rencana besok.',
      priority: 'Sedang',
      day: dayName(today),
      time: atTime(presetBaseDate, 20, 30),
      active: true,
    },
    {
      title: 'Belajar Skill Baru',
      description: 'Belajar mandiri 45 menit.',
      priority: 'Rendah',
      day: 'sabtu',
      time: atTime(presetBaseDate, 9, 0),
      active: true,
    },
  ];

  const weeklyRequiredDrafts = [
    {
      title: 'Kelas Algoritma',
      day: 'senin',
      startTime: '08:00',
      endTime: '09:40',
      location: 'Ruang A-302',
      note: 'Bawa laptop dan catatan minggu lalu.',
      priority: 'Tinggi',
      active: true,
    },
    {
      title: 'Kelas Basis Data',
      day: 'senin',
      startTime: '13:00',
      endTime: '14:40',
      location: 'Lab Komputer 2',
      note: 'Praktikum query join.',
      priority: 'Tinggi',
      active: true,
    },
    {
      title: 'Mentoring Skripsi',
      day: 'rabu',
      startTime: '10:00',
      endTime: '11:00',
      location: 'Ruang Dosen 5',
      note: 'Update progres bab 3.',
      priority: 'Sedang',
      active: true,
    },
  ];

  await prisma.user.upsert({
    where: { id: TEST_USER_ID },
    update: {
      email: TEST_USER_EMAIL,
      name: TEST_USER_NAME,
      bio: TEST_USER_BIO,
      avatarUrl: TEST_USER_AVATAR_URL,
      passwordHash: hashPassword(TEST_USER_PASSWORD),
    },
    create: {
      id: TEST_USER_ID,
      email: TEST_USER_EMAIL,
      name: TEST_USER_NAME,
      bio: TEST_USER_BIO,
      avatarUrl: TEST_USER_AVATAR_URL,
      passwordHash: hashPassword(TEST_USER_PASSWORD),
    },
  });

  await prisma.task.deleteMany({
    where: { userId: TEST_USER_ID },
  });

  await prisma.preset.deleteMany({
    where: { userId: TEST_USER_ID },
  });

  await prisma.weeklyRequiredTask.deleteMany({
    where: { userId: TEST_USER_ID },
  });

  await prisma.task.createMany({
    data: taskDrafts.map((task) => ({
      ...task,
      consequence: buildConsequence(task.title, task.priority),
      userId: TEST_USER_ID,
    })),
  });

  await prisma.preset.createMany({
    data: presetDrafts.map((preset) => ({
      ...preset,
      userId: TEST_USER_ID,
    })),
  });

  await prisma.weeklyRequiredTask.createMany({
    data: weeklyRequiredDrafts.map((weeklyTask) => ({
      ...weeklyTask,
      userId: TEST_USER_ID,
    })),
  });

  const taskCount = await prisma.task.count({ where: { userId: TEST_USER_ID } });
  const presetCount = await prisma.preset.count({ where: { userId: TEST_USER_ID } });
  const weeklyRequiredCount = await prisma.weeklyRequiredTask.count({
    where: { userId: TEST_USER_ID },
  });

  console.log(
    `Seed selesai. User: ${TEST_USER_EMAIL}, Tasks: ${taskCount}, Presets: ${presetCount}, WeeklyRequired: ${weeklyRequiredCount}`
  );
}

main()
  .catch((error) => {
    console.error('Seed gagal:', error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
