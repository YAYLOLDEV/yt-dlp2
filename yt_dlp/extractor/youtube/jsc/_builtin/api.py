from __future__ import annotations

import json
import urllib.parse
from collections.abc import Generator

from yt_dlp.extractor.youtube.jsc.provider import (
    JsChallengeProvider,
    JsChallengeProviderError,
    JsChallengeProviderResponse,
    JsChallengeRequest,
    JsChallengeResponse,
    JsChallengeType,
    NChallengeInput,
    NChallengeOutput,
    SigChallengeInput,
    SigChallengeOutput,
    register_preference,
    register_provider,
)
from yt_dlp.extractor.youtube.pot._provider import BuiltinIEContentProvider
from yt_dlp.networking import Request
from yt_dlp.utils import traverse_obj, urljoin


@register_provider
class ApiJCP(JsChallengeProvider, BuiltinIEContentProvider):
    PROVIDER_NAME = 'api'
    PROVIDER_VERSION = '1.0.0'
    BUG_REPORT_LOCATION = 'https://github.com/kikkia/yt-dlp-decipher'
    _SUPPORTED_TYPES = [JsChallengeType.SIG, JsChallengeType.N]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_base_url = self._configuration_arg(
            'api_url', default=['https://cipher.kikkia.dev'])[0]
        self._api_token = self._configuration_arg('api_token', default=[''])[0]

    def is_available(self) -> bool:
        """Check if the API provider is available"""
        # Always available since it's an external API
        return True

    def _real_bulk_solve(self, requests: list[JsChallengeRequest]) -> Generator[JsChallengeProviderResponse, None, None]:
        """Solve multiple JS challenges using the external API"""
        for request in requests:
            try:
                if request.type == JsChallengeType.SIG:
                    output = self._solve_sig_challenges(request.video_id, request.input)
                    yield JsChallengeProviderResponse(
                        request=request,
                        response=JsChallengeResponse(type=request.type, output=output)
                    )
                else:
                    output = self._solve_nsig_challenges(request.video_id, request.input)
                    yield JsChallengeProviderResponse(
                        request=request,
                        response=JsChallengeResponse(type=request.type, output=output)
                    )
            except Exception as e:
                yield JsChallengeProviderResponse(request=request, error=e)

    def _solve_sig_challenges(self, video_id, sig_input: SigChallengeInput) -> SigChallengeOutput:
        """Solve signature challenges using the API"""
        results = {}
        player_url = urljoin('https://www.youtube.com', sig_input.player_url)

        self.logger.trace(f'Solving {len(sig_input.challenges)} sig challenges using API with player {player_url}')

        for challenge in sig_input.challenges:
            try:
                payload = {
                    'encrypted_signature': challenge,
                    'n_param': '',
                    'player_url': player_url,
                }
                response = self._api_request('decrypt_signature', payload, video_id)
                decrypted_sig = response.get('decrypted_signature', '')
                
                if not decrypted_sig:
                    raise JsChallengeProviderError(f'API returned empty signature for challenge', expected=False)
                
                results[challenge] = decrypted_sig
                self.logger.debug(f'Decrypted sig via API: {challenge[:20]}... => {decrypted_sig[:20]}...')
            except Exception as e:
                raise JsChallengeProviderError(f'Failed to decrypt signature: {e}', expected=False) from e

        return SigChallengeOutput(results=results)

    def _solve_nsig_challenges(self, video_id, nsig_input: NChallengeInput) -> NChallengeOutput:
        """Solve n-parameter challenges using the API"""
        results = {}
        player_url = urljoin('https://www.youtube.com', nsig_input.player_url)

        self.logger.trace(f'Solving {len(nsig_input.challenges)} nsig challenges using API with player {player_url}')

        for challenge in nsig_input.challenges:
            try:
                payload = {
                    'encrypted_signature': '',
                    'n_param': challenge,
                    'player_url': player_url,
                }
                response = self._api_request('decrypt_signature', payload, video_id)
                decrypted_n = response.get('decrypted_n_sig', '')
                
                if not decrypted_n:
                    raise JsChallengeProviderError(f'API returned empty n-parameter for challenge', expected=False)
                
                results[challenge] = decrypted_n
                self.logger.debug(f'Decrypted nsig via API: {challenge[:20]}... => {decrypted_n[:20]}...')
            except Exception as e:
                raise JsChallengeProviderError(f'Failed to decrypt n-parameter: {e}', expected=False) from e

        return NChallengeOutput(results=results)

    def _api_request(self, endpoint: str, data: dict, video_id: str | None = None) -> dict:
        """Make a POST request to the API"""
        url = f'{self._api_base_url}/{endpoint}'
        headers = {
            'Content-Type': 'application/json',
        }
        
        if self._api_token:
            headers['Authorization'] = self._api_token

        try:
            request = Request(
                url,
                data=json.dumps(data).encode('utf-8'),
                headers=headers,
            )
            
            response_data = self.ie._download_json(
                request,
                video_id,
                note=False,
                errnote=f'Failed to contact API at {url}',
                fatal=True,
            )
            
            return response_data
        except Exception as e:
            raise JsChallengeProviderError(f'API request to {url} failed: {e}', expected=False) from e


@register_preference(ApiJCP)
def preference(provider: JsChallengeProvider, requests: list[JsChallengeRequest]) -> int:
    """Set high priority for the API provider"""
    return 900  # Higher priority than other providers
