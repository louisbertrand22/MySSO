export default function Footer() {
  return (
    <footer className="bg-gray-900 border-t border-gray-800 mt-auto">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <p className="text-center text-sm text-gray-300">
          MySSO - Système d'authentification créé par{' '}
          <span className="font-semibold text-indigo-400">Louis BERTRAND</span>
        </p>
        <p className="text-center text-xs text-gray-400 mt-2">
          Ce service d'authentification unique (SSO) permet de s'authentifier de manière centralisée sur toutes mes futures applications
        </p>
      </div>
    </footer>
  );
}
