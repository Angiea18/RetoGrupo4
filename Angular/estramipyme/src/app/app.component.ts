import { Component, ElementRef, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { GraphsComponent } from './components/graphs/graphs.component';

import { Question } from '@models/question.model';
import { RenderFormDirective } from './directives/render-form.directive';
import { FooterComponent } from './pages/components/footer/footer.component';
import { GlobalProviderService } from '@services/global-provider.service';
import { GraphCircleComponent } from './components/graph-circle/graph-circle.component';
import { LoginComponent } from './pages/login/login.component';
import { RegisterComponent } from './pages/register/register.component';

type Answers =
  | {}
  | {
      [key: string | number]: string;
    };

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    RouterOutlet,
    GraphsComponent,
    RenderFormDirective,
    FooterComponent,
    GraphCircleComponent,
    LoginComponent,
    RegisterComponent,
  ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent implements OnInit {
  isLoged = signal<boolean>(false);
  mobileOpen = signal<boolean>(false);
  progress = signal(0);
  title: String = 'estramipyme';
  private answers: any = {};
  private el: ElementRef;
  private numberOfQuestions = 50;
  #nav: HTMLHtmlElement | any;
  #navHeight: HTMLHtmlElement | any;
  #header: HTMLHtmlElement | any;
  #allSections: HTMLHtmlElement | any;
  #progress: HTMLHtmlElement | any;
  #navLinks: HTMLHtmlElement | any;

  // private provider = inject(GlobalProviderService)
  globalProvider!: GlobalProviderService;

  constructor(el: ElementRef, globalProvider: GlobalProviderService) {
    this.el = el;
    this.globalProvider = globalProvider;
  }

  toggleLogin() {
    this.isLoged.update((prevValue) => !prevValue);
  }

  toggleMobileOpen() {
    this.mobileOpen.update((prevValue) => !prevValue);
  }

  ngOnInit() {
    this.globalProvider.IsLogged$.subscribe((value) => {
      console.log('is logged in provider');
      this.isLoged.set(value);
    });

    this.globalProvider.Progress$.subscribe((value) => {
      this.progress.set(value);
    });
    //const startTest = document.querySelector(".start-test");
    console.log('elemento nava');
    this.#navLinks = this.el.nativeElement.querySelector('.nav__links');
    this.#nav = this.el.nativeElement.querySelector('.nav');
    this.#navHeight = this.#nav.getBoundingClientRect().height;
    const startTest = this.el.nativeElement.querySelector('.start-test');
    this.#header = this.el.nativeElement.querySelector('.header');
    this.#allSections =
      this.el.nativeElement.querySelectorAll('.section__main');
    this.#progress = document.getElementById('progreso');

    startTest.addEventListener('click', this._handlerStartTest.bind(this));

    // Hacer el fade in de la barra de navegacón
    this.#nav.addEventListener('mouseover', this._handleHover.bind(0.5));
    this.#nav.addEventListener('mouseout', this._handleHover.bind(1));
    const sectionObserver = new IntersectionObserver(
      this._revealSection.bind(this),
      {
        root: null,
        threshold: 0.15,
      }
    );
    this.#navLinks.addEventListener('click', function (e: any) {
      e.preventDefault();

      // Matching strategy
      if (e.target.classList.contains('nav__link')) {
        const id = e.target.getAttribute('href');
        document.querySelector(id).scrollIntoView({ behavior: 'smooth' });
      }
    });
    this.#allSections.forEach(function (section: HTMLHtmlElement) {
      sectionObserver.observe(section);
      section.classList.add('section--hidden');
    });
    const headerObserver = new IntersectionObserver(
      this._createStickyNav.bind(this),
      {
        root: null,
        threshold: 0,
        rootMargin: `${this.#navHeight}px`,
      }
    );
    headerObserver.observe(this.#header);

    this._setupResultsButton();

    this._setupResultsButton();
  }

  resetForm(): void {
    this.globalProvider.reset();
  }

  _revealSection(
    entries: IntersectionObserverEntry[],
    observer: IntersectionObserver
  ) {
    console.log('reveal section');
    const [entry] = entries;
    if (!entry.isIntersecting) return;
    this.el.nativeElement
      .querySelectorAll('.nav__link')
      .forEach((link: HTMLElement) => link.classList.remove('selected-link'));
    const id: String = entry.target.id;
    const element: HTMLHtmlElement = this.el.nativeElement.querySelector(
      `.nav__link[href="#${id}"]`
    );

    this.el.nativeElement
      .querySelector(`.nav__link[href="#${id}"]`)
      .classList.add('selected-link');
  }

  _handleHover(e: any) {
    if (e.target.classList.contains('nav__link')) {
      const link = e.target;
      const siblings = link.closest('.nav').querySelectorAll('.nav__link');
      const logo = link.closest('.nav').querySelector('img');

      siblings.forEach((el: any) => {
        if (el !== link) el.style.opacity = this;
      });
      logo.style.opacity = this;
    }
  }

  _handlerStartTest(e: MouseEvent) {
    console.log('event targe');
    const target = e.target as unknown as HTMLElement;
    e.preventDefault();

    const id: String | null = target.getAttribute('href');
    this.el.nativeElement
      .querySelector(id)
      .scrollIntoView({ behavior: 'smooth' });
  }

  _getProgress() {
    if (!this.answers) return 0;
    if (!this.numberOfQuestions) return 0;
    return Math.ceil(
      (Object.keys(this.answers).length / this.numberOfQuestions) * 100
    );
  }

  _createStickyNav(entries: any) {
    const [entry] = entries;
    if (entry.isIntersecting) this.#nav.classList.add('hidden');
    else this.#nav.classList.remove('hidden');
  }

  _setupResultsButton() {
    const showResultsButton = this.el.nativeElement.querySelector(
      '.section-see-results .btn--show-modal'
    );

    if (!showResultsButton) {
      console.error('Botón "Ver resultados" no encontrado.');
      return;
    }

    showResultsButton.addEventListener('click', () => {
      const fieldsets = this.el.nativeElement.querySelectorAll(
        '.form-container fieldset'
      );

      // Resetear cualquier error previo
      fieldsets.forEach((fieldset: HTMLHtmlElement) => {
        fieldset.classList.remove('fieldset-error');
      });

      if (
        Object.entries(this.globalProvider.answers()).length <
        this.globalProvider.numberOfQuestions
      ) {
        const answerIds = Object.keys(this.globalProvider.answers());

        fieldsets.forEach((fieldset: HTMLHtmlElement) => {
          const current = fieldset.getAttribute('data-question-id');
          if (current) {
            if (!answerIds.includes(current))
              fieldset.classList.add('fieldset-error');
          }
        });

        const questionsKeys = Array.from(
          { length: this.globalProvider.numberOfQuestions },
          (_, i) => String(i + 1)
        );

        const queue = questionsKeys.filter(
          (element) => !answerIds.includes(element)
        );

        const currentTarget: HTMLHtmlElement =
          this.el.nativeElement.querySelector(
            `.form-container fieldset[data-question-id="${queue[0]}"]`
          );
        currentTarget.scrollIntoView({
          behavior: 'smooth',
          block: 'center',
        });
      } else {
        console.log('Todas las preguntas han sido respondidas.');
        const radarSection =
          this.el.nativeElement.querySelector('.section-radar');
        if (radarSection) {
          radarSection.scrollIntoView({
            behavior: 'smooth',
            block: 'center',
          });
        }
      }
    });
  }
}
