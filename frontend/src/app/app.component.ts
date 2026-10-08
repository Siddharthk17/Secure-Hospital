import { Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  template: `
  <div class="topbar">
    <a class="brand" routerLink="/">
      <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="1" y="1" width="22" height="22" rx="6" fill="none" stroke="#8fc2ff" stroke-width="1.6"/><path d="M12 6.5v11M6.5 12h11" stroke="#ffd9a3" stroke-width="2.4" stroke-linecap="round"/><path d="M4 12h3.2l1.6-3.2 2.4 6.4 1.6-3.2H20" fill="none" stroke="#ffffff" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span>SECURE EXCHANGE<small>AES-256-GCM · RSA-OAEP · RSA-PSS · CNS FA</small></span>
    </a>
    <nav *ngIf="auth.loggedIn()">
      <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{exact:true}">Dashboard</a>
      <a routerLink="/compose" routerLinkActive="active">Send Report</a>
      <a routerLink="/inbox" routerLinkActive="active">Inbox</a>
      <a routerLink="/patients" routerLinkActive="active">Patients</a>
      <a routerLink="/attacker-lab" routerLinkActive="active">Attacker Lab</a>
      <a routerLink="/keys" routerLinkActive="active">Keys</a>
      <a routerLink="/audit" routerLinkActive="active">Audit</a>
      <a routerLink="/security" routerLinkActive="active">Security</a>
      <a href="#" (click)="logout($event)" title="Logged in as {{auth.username()}}">Logout ({{auth.username()}})</a>
    </nav>
    <nav *ngIf="!auth.loggedIn()">
      <a routerLink="/security" routerLinkActive="active">Security design</a>
      <a routerLink="/login" routerLinkActive="active">Login</a>
    </nav>
  </div>
  <div class="wrap"><main><router-outlet></router-outlet></main>
    <footer>CONFIDENTIALITY · INTEGRITY · AUTHENTICATION · NON-REPUDIATION · AVAILABILITY — CNS FA 2026-27</footer>
  </div>`,
})
export class AppComponent {
  auth = inject(AuthService);
  router = inject(Router);
  logout(e: Event) {
    e.preventDefault();
    this.auth.logout();
    this.router.navigate(['/login']);
  }
}
