import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { ButtonLink } from '@/components/ui/Button';
import { SearchIcon } from '@/components/ui/Icons';

export const metadata = { title: 'Page introuvable' };

export default function NotFound() {
  return (
    <AuthShell
      icon={<StatusIcon tone="neutral"><SearchIcon size={20} /></StatusIcon>}
      title="Page introuvable"
      description="Cette adresse ne correspond à aucune page. Le lien est peut-être incomplet ou la page a été déplacée."
    >
      <div className="space-y-2.5">
        <ButtonLink href="/dashboard" className="w-full">Aller à mon compte</ButtonLink>
        <ButtonLink href="/" variant="ghost" className="w-full">Accueil</ButtonLink>
      </div>
    </AuthShell>
  );
}
