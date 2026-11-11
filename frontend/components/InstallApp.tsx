'use client';

import { useState } from 'react';
import { promptInstall, useInstallState } from '@/lib/pwa';
import { Button } from './ui/Button';
import { CheckIcon, DownloadIcon, PlusSquareIcon, ShareIcon } from './ui/Icons';
import { useOverlay } from './ui/Overlays';

/** "Install the app" control, adapted to what the current browser supports. */
export default function InstallApp() {
  const state = useInstallState();
  const { toast } = useOverlay();
  const [showIosSteps, setShowIosSteps] = useState(false);

  if (state === 'installed') {
    return (
      <p className="flex items-center gap-2 text-sm text-accent-text">
        <CheckIcon size={16} /> L’application est installée sur cet appareil.
      </p>
    );
  }

  if (state === 'available') {
    return (
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted">Ouvrez MySSO depuis votre écran d’accueil, dans sa propre fenêtre.</p>
        <Button
          variant="secondary"
          size="sm"
          onClick={async () => {
            if (await promptInstall()) toast('MySSO a été ajouté à votre écran d’accueil.');
          }}
        >
          <DownloadIcon size={15} /> Installer l’application
        </Button>
      </div>
    );
  }

  if (state === 'ios') {
    return (
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-muted">Ajoutez MySSO à l’écran d’accueil de votre iPhone ou iPad.</p>
          {!showIosSteps && (
            <Button variant="secondary" size="sm" onClick={() => setShowIosSteps(true)}>
              <DownloadIcon size={15} /> Installer l’application
            </Button>
          )}
        </div>
        {showIosSteps && (
          <ol className="animate-enter space-y-2.5 rounded-[var(--radius-control)] border border-line bg-surface-2 p-3.5 text-sm">
            <li className="flex items-center gap-2.5">
              <span className="tabular grid size-6 shrink-0 place-items-center rounded-full bg-surface text-xs font-semibold">1</span>
              <span>Touchez <ShareIcon size={16} className="mx-0.5 inline -translate-y-px text-accent-text" /> <strong className="font-medium">Partager</strong> dans la barre de Safari.</span>
            </li>
            <li className="flex items-center gap-2.5">
              <span className="tabular grid size-6 shrink-0 place-items-center rounded-full bg-surface text-xs font-semibold">2</span>
              <span>Choisissez <PlusSquareIcon size={16} className="mx-0.5 inline -translate-y-px text-accent-text" /> <strong className="font-medium">Sur l’écran d’accueil</strong>.</span>
            </li>
            <li className="flex items-center gap-2.5">
              <span className="tabular grid size-6 shrink-0 place-items-center rounded-full bg-surface text-xs font-semibold">3</span>
              <span>Touchez <strong className="font-medium">Ajouter</strong> : l’icône MySSO apparaît avec vos apps.</span>
            </li>
          </ol>
        )}
      </div>
    );
  }

  return (
    <p className="text-sm text-muted">
      Pour installer MySSO, ouvrez le menu du navigateur et choisissez « Installer l’application » ou
      « Ajouter à l’écran d’accueil ». Sur ordinateur, Chrome et Edge le proposent aussi dans la barre d’adresse.
    </p>
  );
}
