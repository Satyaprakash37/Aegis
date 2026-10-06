import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Load current user profile if token exists
  useEffect(() => {
    async function loadUser() {
      const token = localStorage.getItem('aegis_token');
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const response = await api.get('/api/auth/me');
        setUser(response.data);
      } catch (err) {
        console.error('Failed to verify existing session:', err);
        localStorage.removeItem('aegis_token');
        localStorage.removeItem('aegis_user');
        setUser(null);
      } finally {
        setLoading(false);
      }
    }

    loadUser();
  }, []);

  const login = async (email, password) => {
    // OAuth2PasswordRequestForm expects form-urlencoded body
    const params = new URLSearchParams();
    params.append('username', email);
    params.append('password', password);

    const tokenResponse = await api.post('/api/auth/login', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { access_token } = tokenResponse.data;
    localStorage.setItem('aegis_token', access_token);

    // Fetch user profile immediately
    const meResponse = await api.get('/api/auth/me', {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });

    const userData = meResponse.data;
    localStorage.setItem('aegis_user', JSON.stringify(userData));
    setUser(userData);
    return userData;
  };

  const register = async (fullName, email, password) => {
    // Register user
    await api.post('/api/auth/register', {
      email,
      password,
      full_name: fullName,
    });

    // Auto-login newly registered user
    return await login(email, password);
  };

  const logout = () => {
    localStorage.removeItem('aegis_token');
    localStorage.removeItem('aegis_user');
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
