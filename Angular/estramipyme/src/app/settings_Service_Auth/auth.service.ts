npm install @angular/core @angular/common @angular/common/http rxjs

import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private loginUrl = 'api/login';
  private refreshUrl = 'api/refresh';
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(!!this.getToken());

  constructor(private http: HttpClient) {}

  /**
   * Perform login with user credentials.
   */
  login(credentials: { username: string; password: string }): Observable<any> {
    return this.http.post<{ token: string }>(this.loginUrl, credentials).pipe(
      map((response) => {
        this.storeToken(response.token);
        this.isAuthenticatedSubject.next(true);
        return response;
      }),
      catchError((error) => {
        console.error('Login failed', error);
        return throwError(() => new Error('Login failed: ' + error.message));
      })
    );
  }

  /**
   * Refresh the JWT token.
   */
  refreshToken(): Observable<any> {
    const token = this.getToken();
    if (!token) {
      return throwError(() => new Error('No token available for refresh'));
    }

    const headers = new HttpHeaders({
      Authorization: `Bearer ${token}`,
    });

    return this.http.post<{ token: string }>(this.refreshUrl, {}, { headers }).pipe(
      map((response) => {
        this.storeToken(response.token);
        return response;
      }),
      catchError((error) => {
        console.error('Token refresh failed', error);
        return throwError(() => new Error('Refresh failed: ' + error.message));
      })
    );
  }

  /**
   * Check if the user is authenticated.
   */
  isAuthenticated(): Observable<boolean> {
    return this.isAuthenticatedSubject.asObservable();
  }

  /**
   * Store the JWT token securely.
   */
  private storeToken(token: string): void {
    localStorage.setItem('jwtToken', token);
  }

  /**
   * Retrieve the JWT token from storage.
   */
  getToken(): string | null {
    return localStorage.getItem('jwtToken');
  }

  /**
   * Logout and clear session data.
   */
  logout(): void {
    localStorage.removeItem('jwtToken');
    this.isAuthenticatedSubject.next(false);
  }
}
