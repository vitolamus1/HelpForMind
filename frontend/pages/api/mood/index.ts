import type { NextApiRequest, NextApiResponse } from 'next';
const BACKEND = process.env.BACKEND_API_BASE || 'http://localhost:3001/api';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', ['GET','POST']);
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  try {
    const r = await fetch(`${BACKEND}/mood`, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: (req.headers.authorization as string) || '',
      },
      body: req.method === 'POST' ? JSON.stringify(req.body || {}) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    return res.status(r.status).json(data);
  } catch {
    return res.status(502).json({ error: 'Upstream error' });
  }
}
