import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {

  credencialArray: any = [
    {
      id: 'cacono',
      credencial: 'Digi credencial',
      icon: 'img'
    },
    {
      id: 'cacono2',
      credencial: 'Gmail credencial',
      icon: 'img'
    },
    {
      id: 'cacono3',
      credencial: 'Linkedin credencial',
      icon: 'img'
    },
    {
      id: 'cacono4',
      credencial: 'Facebook credencial',
      icon: 'img'
    },
    {
      id: 'asdg',
      credencial: 'Twitter credencial',
      icon: 'img'
    },
  ];

  constructor() { }

  ngOnInit(): void {
  }
  
  async getCredencialData(): Promise<any> {
    let response = await fetch('http://127.0.0.1:5000/data_file', {
      'mode': 'no-cors',
      'headers': {
        'Access-Control-Allow-Origin': '*',
      }
    });
    const json = await response.text();
    // just log ‘json’
    console.log(json);
    /* .then(post => {
      console.log(post.title);
    }); */
  }

}
