import type { NextApiRequest, NextApiResponse } from 'next';

const BACKEND_API_BASE = process.env.BACKEND_API_BASE || 'http://localhost:3001/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET' && req.method !== 'DELETE') {
    res.setHeader('Allow', ['GET', 'DELETE']);
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const response = await fetch(`${BACKEND_API_BASE}/ai-chat/history`, {
      method: req.method,
      headers: {
        Authorization: (req.headers.authorization as string) || '',
      },
    });

    const data = await response.json().catch(() => ({}));
    return res.status(response.status).json(data);
  } catch (err: any) {
    return res.status(502).json({ error: 'Upstream error contacting AI service' });
  }
}
