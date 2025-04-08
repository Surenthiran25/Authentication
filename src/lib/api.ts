const API_URL = 'http://localhost:5000/api';

export const api = {
  login: async (email: string, password: string) => {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to login');
    }
    
    return response.json();
  },

  forgotPassword: async (email: string) => {
    const response = await fetch(`${API_URL}/forgot-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to send reset email');
    }
    
    return response.json();
  },

  resetPassword: async (token: string, password: string) => {
    const response = await fetch(`${API_URL}/reset-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token, password }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to reset password');
    }
    
    return response.json();
  },
};