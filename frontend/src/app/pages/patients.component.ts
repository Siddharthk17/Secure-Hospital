import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-patients',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <span class="eyebrow">REGISTRY · CONSENTED IDENTITIES</span>
  <h1 class="hero-title">Patients.</h1>
  <div class="grid2">
    <div class="card"><h2>Register</h2>
      <label>MRN <input [(ngModel)]="m.mrn" placeholder="MRN-1004" /></label>
      <label>Full name <input [(ngModel)]="m.full_name" /></label>
      <div class="grid2">
        <label>DOB <input [(ngModel)]="m.dob" type="date" /></label>
        <label>Blood <input [(ngModel)]="m.blood_group" placeholder="O+" /></label>
      </div>
      <label>Allergies <input [(ngModel)]="m.allergies" /></label>
      <button class="primary" (click)="add()">Add patient</button>
      <div *ngIf="msg" class="alert ok">{{msg}}</div><div *ngIf="err" class="alert bad">{{err}}</div>
    </div>
    <div class="card"><h2>Directory ({{list().length}})</h2>
      <table><tr><th>MRN</th><th>Name</th><th>Blood</th></tr>
      <tr *ngFor="let p of list()"><td class="mono">{{p.mrn}}</td><td>{{p.full_name}}</td><td>{{p.blood_group}}</td></tr></table>
    </div>
  </div>`,
})
export class PatientsComponent implements OnInit {
  private api = inject(ApiService);
  list = signal<any[]>([]);
  m: any = { mrn: '', full_name: '', dob: '', blood_group: '', allergies: '' };
  msg = ''; err = '';
  ngOnInit() { this.refresh(); }
  refresh() { this.api.patients().subscribe({ next: (r) => this.list.set(r) }); }
  add() {
    this.msg = ''; this.err = '';
    this.api.addPatient(this.m).subscribe({ next: () => { this.msg = 'Patient registered.'; this.m = { mrn: '', full_name: '', dob: '', blood_group: '', allergies: '' }; this.refresh(); }, error: (e) => (this.err = JSON.stringify(e?.error || e)) });
  }
}
