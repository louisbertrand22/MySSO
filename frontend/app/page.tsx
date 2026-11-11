'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { Logo, LogoMark } from '@/components/Brand';
import { ButtonLink } from '@/components/ui/Button';
import { PageLoader } from '@/components/ui/Feedback';
import { AppsIcon, ArrowRightIcon, CheckIcon, DeviceIcon, KeyIcon } from '@/components/ui/Icons';

const POINTS = [
  {
    icon: KeyIcon,
    title: 'Un mot de passe, toutes les applications',
    text: 'Vous vous connectez une fois sur MySSO, puis les applications partenaires vous reconnaissent.',
  },
  {
    icon: AppsIcon,
    title: 'Vous décidez qui accède à quoi',
    text: 'Chaque application demande votre accord et ne voit que les informations que vous acceptez de partager.',
  },
  {
    icon: DeviceIcon,
    title: 'Vos appareils sous les yeux',
    text: 'Retrouvez chaque session ouverte et fermez celles que vous ne reconnaissez pas.',
  },
];

/** Static miniature of the consent screen, used as the hero illustration. */
function ConsentPreview() {
  return (
    <div className="relative" aria-hidden="true">
      <div className="absolute -inset-4 rounded-[28px] bg-dots sm:-inset-6 opacity-70" />
      <div className="relative ml-auto w-full max-w-[340px] rounded-[var(--radius-card)] border border-line bg-surface p-5 shadow-[var(--shadow-pop)]">
        <div className="flex items-center gap-2 text-[13px] font-medium text-muted">
          <LogoMark size={18} /> MySSO
        </div>
        <p className="mt-4 text-[15px] font-semibold leading-snug">
          <span className="text-accent-text">Carnet de notes</span> souhaite accéder à votre compte
        </p>
        <div className="mt-4 flex items-center gap-2.5 rounded-[var(--radius-control)] bg-surface-2 px-2.5 py-2">
          <div className="grid size-7 place-items-center rounded-[6px] bg-accent-soft text-xs font-semibold text-accent-text">C</div>
          <span className="text-[13px]">camille.roussel@exemple.fr</span>
        </div>
        <ul className="mt-4 space-y-2 text-[13px]">
          {['Connaître votre identité', 'Lire votre adresse e-mail'].map((s) => (
            <li key={s} className="flex items-center gap-2">
              <CheckIcon size={14} className="text-accent-text" /> {s}
            </li>
          ))}
        </ul>
        <div className="mt-5 grid grid-cols-2 gap-2">
          <div className="grid h-8 place-items-center rounded-[var(--radius-control)] border border-line text-[13px] font-medium">Refuser</div>
          <div className="grid h-8 place-items-center rounded-[var(--radius-control)] bg-accent text-[13px] font-medium text-accent-fg">Autoriser</div>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const router = useRouter();
  const { user, isLoading } = useAuth();

  useEffect(() => {
    if (!isLoading && user) {
      router.push('/dashboard');
    }
  }, [user, isLoading, router]);

  if (isLoading || user) {
    return <PageLoader />;
  }

  return (
    <div className="flex flex-1 flex-col">
      <header className="mx-auto flex w-full max-w-6xl items-center justify-between px-5 py-5 sm:px-8">
        <Logo />
        <ButtonLink href="/login" variant="ghost" size="sm">Se connecter</ButtonLink>
      </header>

      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-5 pb-20 sm:px-8">
        <section className="grid items-center gap-14 pt-10 pb-16 md:grid-cols-[1.1fr_1fr] md:pt-20 md:pb-24">
          <div className="max-w-xl animate-enter">
            <p className="text-sm font-medium text-accent-text">Authentification unique</p>
            <h1 className="mt-3 text-4xl font-semibold leading-[1.08] tracking-[-0.03em] sm:text-5xl">
              Un seul compte pour toutes vos applications.
            </h1>
            <p className="mt-5 max-w-[52ch] text-[17px] leading-relaxed text-muted">
              MySSO gère votre identité à un seul endroit. Les applications vous demandent l’accès,
              vous choisissez ce que vous partagez, et vous pouvez le retirer quand vous voulez.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <ButtonLink href="/register" size="lg">
                Créer un compte <ArrowRightIcon size={16} />
              </ButtonLink>
              <ButtonLink href="/login" size="lg" variant="secondary">J’ai déjà un compte</ButtonLink>
            </div>
          </div>
          <ConsentPreview />
        </section>

        <section aria-label="Ce que fait MySSO" className="grid gap-px overflow-hidden rounded-[var(--radius-card)] border border-line bg-line md:grid-cols-3">
          {POINTS.map(({ icon: Icon, title, text }) => (
            <div key={title} className="bg-surface p-6">
              <Icon size={20} className="text-accent-text" />
              <h2 className="mt-4 text-[15px] font-semibold">{title}</h2>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{text}</p>
            </div>
          ))}
        </section>
      </main>
    </div>
  );
}
