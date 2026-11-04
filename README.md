# caploc-live
Serviço open source para compartilhamento temporário de localização e SOS do CapLoc.

## Relay RTCM experimental

O stream `https://caploc.safeclim.com/api/rtcm/CAPLOC` retransmite quadros RTCM 3 com CRC24Q válido de uma base conectada por `POST` aos rovers conectados por `GET` NTRIPS. Só há uma base simultânea; o fluxo fica em memória e rovers são desligados quando a base sai. A Central mostra, após login, chaves distintas para base e rover derivadas de `EXPLORER_ADMIN_TOKEN`. As chaves não devem ser colocadas em repositórios ou APKs.

Os receptores precisam ser configurados externamente para emitir e aceitar RTCM. O servidor não calcula correções nem garante RTK FIX; teste com dois receptores e uma referência conhecida antes de coletar. O proxy HTTPS precisa permitir uploads e downloads contínuos sem buffering ou timeout curto.
