import { Button } from "@/components/ui/button";

export default function Home() {
  return (
    <main className="p-6 space-y-4">
      <h1 className="text-2xl font-bold">Test Butonları</h1>
      <Button>Default</Button>
      <Button variant="outline">Outline</Button>
      <Button variant="destructive" size="sm">Delete</Button>
    </main>
  );
}

