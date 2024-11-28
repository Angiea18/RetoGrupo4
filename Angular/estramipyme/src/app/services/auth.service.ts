import { HttpClient } from '@angular/common/http';
import { Inject, Injectable, OnInit } from '@angular/core';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { API_CONSTANTS } from '../config/constants';
import { RegisterDataModel } from '@models/registerdata.models';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  rememberMe: boolean = false;
  private isLogged: BehaviorSubject<boolean> = new BehaviorSubject(false);
  IsLogged$ = this.isLogged.asObservable();

  private apiUrl = API_CONSTANTS.BASE_URL + API_CONSTANTS.AUTH_ENPOINT;

  constructor(@Inject(HttpClient) private http: HttpClient) {
    const token = this.getAuthToken();
    this.setLogging(!!token); // Configura el estado de sesión
  }

  register(userData: RegisterDataModel): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/register`, userData);
  }

  checkToken() {
    const token = this.getAuthToken();
    this.setLogging(!!token); // Solo establece la sesión activa si hay token
  }

  login(credentials: any, rememberMe: boolean = false): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/login`, credentials).pipe(
      tap((res) => {
        console.log(res);
        if (res.token) {
          if (rememberMe) {
            localStorage.setItem('authToken', res.token);
          } else {
            sessionStorage.setItem('authToken', res.token);
          }
          this.setLogging(true);
        }
      })
    );
  }

  onRememberMeChange(event: any) {
    this.rememberMe = event.target.checked;
  }

  getAuthToken() {
    return (
      localStorage.getItem('authToken') || sessionStorage.getItem('authToken')
    );
  }

  // Solicitar el token de restablecimiento de contraseña

  requestPasswordReset(email: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/forgot-password`, email);
  }

  // Cambiar la contraseña con el token de reset
  resetPassword(token: string, newPassword: string): Observable<any> {
    const url = `${this.apiUrl}/reset-password`;
    return this.http.post(url, { token, newPassword });
  }

  setLogging(value: boolean) {
    this.isLogged.next(value);
  }

  logout() {
    localStorage.removeItem('authToken');
    sessionStorage.removeItem('authToken');
    this.setLogging(false);
  }
}
