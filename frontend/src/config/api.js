const API_BASE_URL = import.meta.env.DEV
    ? ''
    : (import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

const buildApiUrl = (path = '') => {
    if (!path) {
        return API_BASE_URL || '/api';
    }

    const normalizedPath = path.startsWith('/') ? path : `/${path}`;

    if (!API_BASE_URL) {
        return normalizedPath;
    }

    return `${API_BASE_URL}${normalizedPath}`;
};

export { API_BASE_URL, buildApiUrl };
