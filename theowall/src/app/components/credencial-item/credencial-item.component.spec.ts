import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CredencialItemComponent } from './credencial-item.component';

describe('CredencialItemComponent', () => {
  let component: CredencialItemComponent;
  let fixture: ComponentFixture<CredencialItemComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ CredencialItemComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CredencialItemComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
