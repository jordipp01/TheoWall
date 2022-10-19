import { Component, OnInit, Input } from '@angular/core';

@Component({
  selector: 'app-credencial-item',
  templateUrl: './credencial-item.component.html',
  styleUrls: ['./credencial-item.component.scss']
})
export class CredencialItemComponent implements OnInit {
  @Input() idCred: string = '12345';
  @Input() credencial: string = 'Digi password';

  constructor() { }

  ngOnInit(): void {
  }

}
