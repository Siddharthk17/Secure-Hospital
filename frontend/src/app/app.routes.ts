import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login.component';
import { DashboardComponent } from './pages/dashboard.component';
import { PatientsComponent } from './pages/patients.component';
import { ComposeComponent } from './pages/compose.component';
import { InboxComponent } from './pages/inbox.component';
import { ReportDetailComponent } from './pages/report-detail.component';
import { KeysComponent } from './pages/keys.component';
import { AuditComponent } from './pages/audit.component';
import { AttackerLabComponent } from './pages/attacker-lab.component';
import { SecurityComponent } from './pages/security.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: '', component: DashboardComponent, canActivate: [authGuard] },
  { path: 'patients', component: PatientsComponent, canActivate: [authGuard] },
  { path: 'compose', component: ComposeComponent, canActivate: [authGuard] },
  { path: 'inbox', component: InboxComponent, canActivate: [authGuard] },
  { path: 'report/:id', component: ReportDetailComponent, canActivate: [authGuard] },
  { path: 'keys', component: KeysComponent, canActivate: [authGuard] },
  { path: 'audit', component: AuditComponent, canActivate: [authGuard] },
  { path: 'attacker-lab', component: AttackerLabComponent, canActivate: [authGuard] },
  { path: 'security', component: SecurityComponent },
  { path: '**', redirectTo: '' },
];
