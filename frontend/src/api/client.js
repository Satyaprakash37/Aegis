import axios from 'axios';

// Base API client
const api = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach bearer token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('aegis_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: handle 401 unauthorized
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Do not redirect if already on auth routes
      const path = window.location.pathname;
      if (path !== '/login' && path !== '/register') {
        localStorage.removeItem('aegis_token');
        localStorage.removeItem('aegis_user');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;
