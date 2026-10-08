import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';

const MODES = [
  ['flip_bit', '✂️ Flip 1 bit on the wire', 'Active MITM bit-flip → must fail AES-GCM tag'],
  ['truncate', '🧩 Truncate ciphertext', 'Packet cutter → GCM + length failure'],
  ['forge_sig', '🖊️ Forge signature', 'Impersonation → RSA-PSS verify must fail'],
  ['hash_swap', '🔁 Swap stored hash', 'Metadata tamper → digest mismatch (+sig fail)'],
  ['replay_copy', '🔂 Replay old envelope', 'Duplicate delivery → nonce cache + AAD + timestamp'],
  ['wrong_recipient', '🕵️ Attacker steals envelope', 'No private key → OAEP unwrap impossible'],
];

@Component({
  selector: 'app-attacker-lab',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <span class="eyebrow">LIVE MITM SIMULATOR · EVALUATORS CLICK HERE</span>
  <h1 class="hero-title">Attacker Lab — <em>try to break it.</em></h1>
  <p class="muted">Pick any of your reports, pick an attack, watch the <b>real verification pipeline</b> catch it. Nothing stored is mutated — attacks run on tampered clones.</p>
  <div class="card">
    <div class="grid2">
      <label>Target report
        <select [(ngModel)]="targetId">
          <option value="">— choose —</option>
          <option *ngFor="let r of reports()" [value]="r.id">{{r.subject}} · {{r.sender}}→{{r.recipient}} · {{r.status}}</option>
        </select></label>
      <label>Attack
        <select [(ngModel)]="mode">
          <option *ngFor="let m of modes" [value]="m[0]">{{m[1]}}</option>
        </select></label>
    </div>
    <p class="muted">{{modeDesc()}}</p>
    <button class="danger" (click)="fire()" [disabled]="!targetId || busy">{{busy?'Attacking…':'🚀 Launch attack'}}</button>
  </div>
  <div *ngIf="result" class="card">
    <h2>Verdict: <span class="badge" [class.ok]="result.caught" [class.bad]="!result.caught">{{result.verdict}}</span></h2>
    <h3>Caught by</h3>
    <ul><li *ngFor="let b of result.by">{{b}}</li></ul>
    <p class="muted">{{result.lesson}}</p>
    <details *ngIf="result.forensics"><summary>Forensics (raw booleans)</summary>
      <pre class="mono">{{result.forensics | json}}</pre></details>
  </div>
  <div class="card steps"><h2>Script for the demo (60 seconds)</h2>
    <ol>
      <li>“This is a live wiretap. I flip <b>one bit</b> of ciphertext…” → click <b>Launch</b> → <b>GCM tag FAIL</b>.</li>
      <li>“Now I forge the doctor's signature…” → <b>RSA-PSS INVALID</b> — impersonation impossible without the private key.</li>
      <li>“I replay last week's envelope…” → <b>rejected by nonce cache + AAD + timestamp</b>.</li>
      <li>“And if I just steal the message?” → <b>unreadable — only the recipient unwraps the DEK</b>.</li>
    </ol>
  </div>`,
})
export class AttackerLabComponent implements OnInit {
  private api = inject(ApiService);
  reports = signal<any[]>([]);
  targetId = ''; mode = 'flip_bit'; busy = false; result: any = null;
  modes = MODES;
  modeDesc() { return MODES.find((m) => m[0] === this.mode)?.[2] || ''; }
  ngOnInit() {
    this.api.inbox().subscribe({ next: (r) => this.reports.set([...this.reports(), ...r]) });
    this.api.sent().subscribe({ next: (r) => this.reports.set([...this.reports(), ...r]) });
  }
  fire() {
    this.busy = true; this.result = null;
    this.api.attack(this.targetId, this.mode).subscribe({
      next: (r) => { this.result = r; this.busy = false; },
      error: (e) => { this.result = { verdict: 'ERROR', caught: false, by: [JSON.stringify(e?.error || e)], lesson: '' }; this.busy = false; },
    });
  }
}
