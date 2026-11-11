export default function Footer() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex max-w-6xl flex-col gap-1 px-5 py-5 text-[13px] text-subtle sm:flex-row sm:items-center sm:justify-between sm:px-8">
        <p>MySSO · authentification unique, conçue par Louis Bertrand</p>
        <p className="tabular">© {new Date().getFullYear()}</p>
      </div>
    </footer>
  );
}
