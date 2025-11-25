import axios from 'axios';

export const API_BASE = 'http://localhost:3001/api';

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: false,
});

export function setAuthToken(token?: string | null) {
  if (token) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common['Authorization'];
  }
}
