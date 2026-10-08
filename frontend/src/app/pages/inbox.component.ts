import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
  <span class="eyebrow">INBOUND · DECRYPT + TRIPLE-VERIFY</span>
  <h1 class="hero-title">Inbox <em>& sent.</em></h1>
  <div class="card">
    <input [(ngModel)]="q" (ngModelChange)="doSearch()" placeholder="Search subject / MRN / patient…" />
    <div style="margin:8px 0">
      <button [class.primary]="tab==='inbox'" (click)="tab='inbox';load()">Inbox ({{inbox().length}})</button>
      <button [class.primary]="tab==='sent'" (click)="tab='sent';load()">Sent ({{sent().length}})</button>
    </div>
    <table>
      <tr><th>Subject</th><th>Patient</th><th>From → To</th><th>Status</th><th>Sent</th><th></th></tr>
      <tr *ngFor="let r of rows()">
        <td>{{r.subject}}</td><td class="mono">{{r.patient_mrn}}</td>
        <td class="mono">{{r.sender}} → {{r.recipient}}</td>
        <td><span class="badge" [class.ok]="r.status==='OPENED'" [class.bad]="r.status==='TAMPER_ALERT'" [class.warn]="r.status!=='OPENED'&&r.status!=='TAMPER_ALERT'">{{r.status}}</span></td>
        <td class="muted">{{r.sent_at | date:'short'}}</td>
        <td><a [routerLink]="['/report', r.id]">Open →</a></td>
      </tr>
    </table>
    <p class="muted" *ngIf="!rows().length">No reports. Send one from Compose.</p>
  </div>`,
})
export class InboxComponent implements OnInit {
  private api = inject(ApiService);
  tab: 'inbox' | 'sent' = 'inbox';
  inbox = signal<any[]>([]); sent = signal<any[]>([]);
  q = '';
  rows() { return this.tab === 'inbox' ? this.inbox() : this.sent(); }
  ngOnInit() { this.load(); }
  load() {
    this.api.inbox().subscribe({ next: (r) => this.inbox.set(r) });
    this.api.sent().subscribe({ next: (r) => this.sent.set(r) });
  }
  doSearch() {
    if (!this.q.trim()) return this.load();
    this.api.search(this.q).subscribe({ next: (r) => { this.inbox.set(r.filter((x: any) => x.recipient)); this.sent.set(r); } });
  }
}
