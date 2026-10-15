Start: node server.js | First register = Admin


=== UPDATE KAISE KARE (v1.1.0+) ===
1. Naya version banao, package.json me "version" badha do (jaise 1.2.0), poora folder zip karo.
2. Admin Panel -> Update -> zip chuno -> "Zip check karo" -> "Update apply karo".
3. Sirf code badalta hai. data/, uploads/, public/uploads/ aur login safe rehte hain.
   Zip ke andar ka data/ aur uploads/ ignore hota hai.
4. Har update se pehle data/backups/ me backup banta hai (last 3). Galti ho to Update page se Rollback.
5. Login 1 saal tak rehta hai. Cloud host (Render/Railway) par environment variable JWT_SECRET
   (koi lamba random text) set karo, taaki redeploy par bhi login na jaye.
Pehli baar: purani website ki data/ aur public/uploads/ folders is naye folder me copy karke chalao.
