import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-security',
  standalone: true,
  imports: [CommonModule],
  template: `
  <span class="eyebrow">CNS MAPPING · CIA + AN + A</span>
  <h1 class="hero-title">Security design, <em>down to the primitives.</em></h1>
  <div class="card">
    <h2>Block diagram — sealed-envelope flow</h2>
<pre class="mono">┌──────────┐  canonical JSON (+nonce/msg_id/ts)   ┌─────────────────────┐
│  SENDER  │ ───────────────────────────────────▶ │  SEAL (server, TLS) │
│ Dr. Asha │                                      │ ① SHA-256 digest    │
└──────────┘                                      │ ② DEK←CSPRNG, iv    │
      ▲                                           │ ③ AES-256-GCM(DEK)  │
      │ sign w/ RSA-PSS                           │ ④ OAEP-wrap DEK     │
      │ private key                               │ ⑤ PSS-sign digest   │
┌──────────┐  CA-certified public keys            │ ⑥ store CT-ONLY     │
│ HOSPITAL │ ───────────────────────────────────▶ │ ⑦ hash-chain audit  │
│    CA    │                                      └─────────┬───────────┘
└──────────┘                                                │ TLS 1.2+
                                                  ┌─────────▼───────────┐
                                                  │   RECIPIENT open    │
                                                  │ GCM tag → SHA-256 → │
                                                  │ PSS verify → replay │
                                                  │ check → plaintext   │
                                                  └─────────────────────┘</pre>
  </div>
  <div class="grid2">
    <div class="card"><h2>CIA + AN + A</h2>
      <div class="kv" *ngIf="ov">
        <ng-container *ngFor="let k of ciaKeys()"><b>{{k}}</b><span>{{ov.cia_plus[k]}}</span></ng-container>
      </div></div>
    <div class="card"><h2>Crypto policy</h2>
      <div class="kv" *ngIf="ov">
        <ng-container *ngFor="let k of polKeys()"><b>{{k}}</b><span class="mono">{{ov.policy[k]}}</span></ng-container>
      </div></div>
  </div>
  <div class="card"><h2>Threats mitigated (STRIDE)</h2>
    <ul><li *ngFor="let t of threats()">✅ {{t}}</li></ul>
  </div>`,
})
export class SecurityComponent implements OnInit {
  private api = inject(ApiService);
  ov: any = null;
  ngOnInit() { this.api.securityOverview().subscribe({ next: (o) => (this.ov = o) }); }
  ciaKeys() { return this.ov ? Object.keys(this.ov.cia_plus) : []; }
  polKeys() { return this.ov ? Object.keys(this.ov.policy) : []; }
  threats() { return this.ov ? this.ov.threats_mitigated : []; }
}
