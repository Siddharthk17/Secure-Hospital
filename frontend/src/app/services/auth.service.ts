import { Injectable, inject, signal } from '@angular/core';
import { HttpClient, HttpInterceptorFn } from '@angular/common/http';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const t = localStorage.getItem('access');
  return next(t ? req.clone({ setHeaders: { Authorization: `Bearer ${t}` } }) : req);
};

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  user = signal<any>(JSON.parse(localStorage.getItem('user') || 'null'));

  loggedIn() { return !!localStorage.getItem('access'); }
  username() { return this.user()?.username || ''; }

  login(username: string, password: string) {
    return this.http.post<any>('/api/auth/login/', { username, password });
  }
  saveSession(tokens: any, profile: any) {
    localStorage.setItem('access', tokens.access);
    localStorage.setItem('refresh', tokens.refresh);
    localStorage.setItem('user', JSON.stringify(profile));
    this.user.set(profile);
  }
  logout() {
    localStorage.removeItem('access');
    localStorage.removeItem('refresh');
    localStorage.removeItem('user');
    this.user.set(null);
  }
}
